// Package oidc is auth's OpenID Connect method: signing in with an identity
// provider by the authorization code flow, with PKCE, state and nonce
// (interface §4.12, §5.14, ADR 0009).
//
// Each provider is a method of its own, oidc_<provider>:
//
//	google, err := oidc.New(cfg)
//	a, err := auth.New(db, cfg, dir, mailer,
//		auth.WithMethods(google),
//		auth.WithFirst(auth.MethodPassword, "oidc_google"),
//	)
//	flow, err := a.SignInWithout(ctx, auth.Cookie())
//	ch, err := a.Challenge(ctx, flow.Token, "oidc_google") // ch.Options: the URL to redirect to
//	// the provider's redirect, on this provider's callback route:
//	flow, err = a.Prove(ctx, token, oidc.Callback("google", r.URL.Query()))
//
// An identity no user holds comes back as flow.Unlinked; the app creates a
// user and calls a.Link. The module verifies with
// github.com/coreos/go-oidc/v3 and golang.org/x/oauth2, whose types appear
// nowhere in its API.
package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/epistemer/auth"
	"github.com/epistemer/cfgx"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/proto"

	"github.com/epistemer/auth/oidc/internal/oidcpb"
)

// Config is one provider's settings, read once by New. An app's generated
// settings implement it when its schema holds
// authschema.Group(authschema.OIDC()).
type Config interface {
	AuthOIDCProvider() string          // [a-z0-9_]{1,27}; the method is oidc_<provider>
	AuthOIDCIssuer() string            // https://accounts.google.com
	AuthOIDCClientID() string          //
	AuthOIDCClientSecret() cfgx.Secret // empty for a public client, which PKCE alone protects
	AuthOIDCRedirectURL() string       // this provider's callback route
	AuthOIDCScopes() []string          // beyond openid; email and profile when empty
	AuthOIDCTwoFactors() bool          // the provider's sign-in counts as two factors
}

const (
	lifetime      = 10 * time.Minute // §5.14.1
	maxQuery      = 8 << 10          // §5.14.3
	maxBody       = 1 << 20          // §5.14.2
	httpTimeout   = 10 * time.Second
	maxAuthAge    = 5 * time.Minute // with two_factors (§5.14.5, §5.14.9)
	clockSkew     = time.Minute
	recordVersion = 1
)

var (
	providerRE = regexp.MustCompile(`^[a-z0-9_]{1,27}$`)
	b64        = base64.RawURLEncoding
)

type method struct {
	name, issuer, clientID, secret, redirect string
	scopes                                   []string
	twoFactors                               bool
	client                                   *http.Client

	mu       sync.Mutex
	d        *discovered // nil until discovery succeeds
	inflight *fetchCall  // a discovery under way, which callers share
}

type discovered struct {
	authURL, tokenURL string
	issParam          bool // the provider sends iss in its redirect (RFC 9207)
	keys              *keySet
}

// New returns the provider's method, to pass to auth.WithMethods. It
// refuses a nil config; a provider name outside [a-z0-9_]{1,27}; an issuer
// that isn't an absolute https URL of at most 767 bytes, with no user,
// query or fragment (http://localhost for development); a redirect URL
// that isn't https (or http://localhost), with no user or fragment; an
// empty client ID; and a scope that holds a space or a control character.
// It makes no network call.
func New(cfg Config) (auth.Method, error) {
	if cfg == nil || isNilConfig(cfg) {
		return nil, errors.New("oidc: New needs a config")
	}
	m := &method{
		issuer: cfg.AuthOIDCIssuer(), clientID: cfg.AuthOIDCClientID(),
		redirect: cfg.AuthOIDCRedirectURL(), twoFactors: cfg.AuthOIDCTwoFactors(),
	}
	provider := cfg.AuthOIDCProvider()
	if !providerRE.MatchString(provider) {
		return nil, errors.New("oidc: auth.oidc.provider isn't [a-z0-9_]{1,27}")
	}
	m.name = "oidc_" + provider
	if len(m.issuer) > 767 || !validURL(m.issuer, false) {
		return nil, errors.New("oidc: auth.oidc.issuer isn't an https URL of at most 767 bytes, with no user, query or fragment")
	}
	if !validURL(m.redirect, true) {
		return nil, errors.New("oidc: auth.oidc.redirect_url isn't an https URL with no user or fragment")
	}
	if m.clientID == "" {
		return nil, errors.New("oidc: auth.oidc.client_id is empty")
	}
	if s := cfg.AuthOIDCClientSecret(); s.IsSet() {
		m.secret = s.Reveal()
	}
	m.scopes = []string{gooidc.ScopeOpenID}
	scopes := cfg.AuthOIDCScopes()
	if len(scopes) == 0 {
		scopes = []string{gooidc.ScopeEmail, gooidc.ScopeProfile}
	}
	for _, s := range scopes {
		if s == "" || strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return nil, errors.New("oidc: a scope in auth.oidc.scopes is empty or holds a space or a control character")
		}
		if s != gooidc.ScopeOpenID {
			m.scopes = append(m.scopes, s)
		}
	}
	m.client = newClient()
	return m, nil
}

// validURL checks a configured URL: absolute, https (http on localhost),
// no user, no fragment, and for an issuer no query.
func validURL(s string, queryOK bool) bool {
	u, err := url.Parse(s)
	if err != nil || !hostOK(u) || u.User != nil || strings.Contains(s, "#") {
		return false
	}
	if !queryOK && (u.RawQuery != "" || u.ForceQuery) {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return u.Hostname() == "localhost"
	}
	return false
}

// endpointOK checks an endpoint discovery named: https with no user, or
// http on localhost when the issuer is there too (§5.14.2).
func (m *method) endpointOK(s string) bool {
	u, err := url.Parse(s)
	if err != nil || !hostOK(u) || u.User != nil || strings.Contains(s, "#") {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	iss, _ := url.Parse(m.issuer)
	return u.Scheme == "http" && u.Hostname() == "localhost" && iss.Hostname() == "localhost"
}

// hostOK requires a host name with no space or control character.
func hostOK(u *url.URL) bool {
	h := u.Hostname()
	return h != "" && strings.IndexFunc(h, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) < 0
}

// newClient is the one HTTP client discovery, the key set and the exchange
// share: a timeout, no redirects, responses cut at 1 MiB (§5.14.2).
func newClient() *http.Client {
	return &http.Client{
		Timeout:       httpTimeout,
		Transport:     capped{http.DefaultTransport},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type capped struct{ rt http.RoundTripper }

func (c capped) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.rt.RoundTrip(r)
	if err == nil {
		resp.Body = limitedBody{io.LimitReader(resp.Body, maxBody), resp.Body}
	}
	return resp, err
}

type limitedBody struct {
	io.Reader
	c io.Closer
}

func (b limitedBody) Close() error { return b.c.Close() }

// Errors of the method's own: fixed texts, never a provider's or a
// library's (§5.14.12). Each takes back the attempt's count (§5.5.6).
var (
	errDiscovery = errors.New("oidc: the provider's discovery failed")
	errProvider  = errors.New("oidc: the provider couldn't be reached or refused the client")
	errState     = errors.New("oidc: the flow's state can't be read")
	errRecord    = errors.New("oidc: a stored identity can't be read")
)

func (m *method) Name() string { return m.name }

// identityKey is an identity's credential key: its issuer and subject
// (§5.14.6).
func (m *method) identityKey(sub string) []byte { return []byte(m.issuer + "\x00" + sub) }

// AddressOnly is true: a callback proves a code the provider issued for
// this flow's verifier, with nothing to guess (§5.14.10).
func (m *method) AddressOnly() bool { return true }

// discover fetches and checks the provider's discovery document once at a
// time, and caches only a success (§5.14.2).
func (m *method) discover(ctx context.Context) (*discovered, error) {
	m.mu.Lock()
	if m.d != nil {
		d := m.d
		m.mu.Unlock()
		return d, nil
	}
	if c := m.inflight; c != nil {
		m.mu.Unlock()
		select {
		case <-c.done:
		case <-ctx.Done():
			return nil, errDiscovery
		}
		m.mu.Lock()
		d := m.d
		m.mu.Unlock()
		if d == nil {
			return nil, errDiscovery
		}
		return d, nil
	}
	c := &fetchCall{done: make(chan struct{})}
	m.inflight = c
	m.mu.Unlock()
	// Not stopped by this caller's cancellation: others wait on it.
	d, err := m.fetchDiscovery(context.WithoutCancel(ctx))
	m.mu.Lock()
	if err == nil {
		m.d = d
	}
	m.inflight = nil
	m.mu.Unlock()
	close(c.done)
	return d, err
}

func (m *method) fetchDiscovery(ctx context.Context) (*discovered, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(m.issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, errDiscovery
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, errDiscovery
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errDiscovery
	}
	var doc struct {
		Issuer   string `json:"issuer"`
		AuthURL  string `json:"authorization_endpoint"`
		TokenURL string `json:"token_endpoint"`
		JWKSURL  string `json:"jwks_uri"`
		IssParam bool   `json:"authorization_response_iss_parameter_supported"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, errDiscovery
	}
	if doc.Issuer != m.issuer || !m.endpointOK(doc.AuthURL) || !m.endpointOK(doc.TokenURL) || !m.endpointOK(doc.JWKSURL) {
		return nil, errDiscovery
	}
	keys := &keySet{uri: doc.JWKSURL, client: m.client}
	return &discovered{authURL: doc.AuthURL, tokenURL: doc.TokenURL, issParam: doc.IssParam, keys: keys}, nil
}

func (m *method) oauth(d *discovered) *oauth2.Config {
	style := oauth2.AuthStyleInHeader
	if m.secret == "" {
		style = oauth2.AuthStyleInParams
	}
	return &oauth2.Config{
		ClientID: m.clientID, ClientSecret: m.secret, RedirectURL: m.redirect, Scopes: m.scopes,
		Endpoint: oauth2.Endpoint{AuthURL: d.authURL, TokenURL: d.tokenURL, AuthStyle: style},
	}
}

func random() string {
	b := make([]byte, 32)
	rand.Read(b)
	return b64.EncodeToString(b)
}

// Start makes state, nonce and the PKCE verifier, and returns the
// authorization URL (§5.14.1).
func (m *method) Start(ctx context.Context, in auth.MethodInput) (any, []byte, error) {
	d, err := m.discover(ctx)
	if err != nil {
		return nil, nil, err
	}
	st := &oidcpb.State{
		Version: recordVersion, State: random(), Nonce: random(), Verifier: random(),
		Expires: in.Now.Add(lifetime).UnixNano(),
	}
	opts := []oauth2.AuthCodeOption{gooidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier)}
	if m.twoFactors {
		opts = append(opts, oauth2.SetAuthURLParam("max_age", "300"))
	}
	u := m.oauth(d).AuthCodeURL(st.State, opts...)
	state, err := proto.Marshal(st)
	if err != nil {
		return nil, nil, errState
	}
	return u, state, nil
}

// Callback is the proof a provider's redirect carries: the provider's
// name, as in oidc_<provider>, and the callback request's query, whole.
func Callback(provider string, query url.Values) auth.Proof {
	q := url.Values{}
	for k, v := range query {
		q[k] = append([]string(nil), v...)
	}
	return callback{"oidc_" + provider, q}
}

type callback struct {
	method string
	query  url.Values
}

func (c callback) Method() string   { return c.method }
func (c callback) String() string   { return c.method + " proof" }
func (c callback) GoString() string { return c.String() }

// Verify checks a callback, exchanges its code and checks the ID token
// (§5.14.3–5.14.7).
func (m *method) Verify(ctx context.Context, in auth.MethodInput, state []byte, p auth.Proof) (auth.MethodResult, error) {
	refuse := func(reason string) (auth.MethodResult, error) { return auth.MethodResult{}, auth.Refuse(reason) }
	// The engine passes a proof only to the method it names.
	c, ok := p.(callback)
	if !ok {
		return refuse("malformed")
	}
	var st oidcpb.State
	if err := proto.Unmarshal(state, &st); err != nil || st.Version != recordVersion {
		return auth.MethodResult{}, errState
	}
	// §5.14.3, in order.
	size := 0
	for k, vs := range c.query {
		size += len(k)
		for _, v := range vs {
			size += len(v)
		}
		if len(vs) != 1 {
			return refuse("malformed")
		}
	}
	if size > maxQuery {
		return refuse("malformed")
	}
	_, hasCode := c.query["code"]
	_, hasErr := c.query["error"]
	if hasCode == hasErr || hasCode && c.query.Get("code") == "" {
		return refuse("malformed")
	}
	if !in.Now.Before(time.Unix(0, st.Expires)) {
		return refuse("expired")
	}
	if subtle.ConstantTimeCompare([]byte(c.query.Get("state")), []byte(st.State)) != 1 {
		return refuse("state")
	}
	d, err := m.discover(ctx)
	if err != nil {
		return auth.MethodResult{}, err
	}
	iss, hasIss := c.query["iss"]
	if hasIss && iss[0] != m.issuer || !hasIss && d.issParam {
		return refuse("issuer")
	}
	if hasErr {
		return refuse("provider_error")
	}
	// §5.14.4, the exchange.
	tok, err := m.oauth(d).Exchange(context.WithValue(ctx, oauth2.HTTPClient, m.client), c.query.Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.Response != nil && re.Response.StatusCode == http.StatusBadRequest && re.ErrorCode != "invalid_client" {
			return refuse("exchange")
		}
		return auth.MethodResult{}, errProvider
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return refuse("token")
	}
	// §5.14.5, the ID token.
	keys := &callKeys{s: d.keys}
	v := gooidc.NewVerifier(m.issuer, keys, &gooidc.Config{
		ClientID: m.clientID, SupportedSigningAlgs: []string{gooidc.RS256, gooidc.ES256},
		Now: func() time.Time { return in.Now },
	})
	idt, err := v.Verify(ctx, raw)
	if err != nil {
		if keys.outage {
			return auth.MethodResult{}, errProvider
		}
		return refuse("token")
	}
	var cl struct {
		Nonce         string          `json:"nonce"`
		AZP           json.RawMessage `json:"azp"`
		IAT           *json.Number    `json:"iat"`
		AuthTime      *json.Number    `json:"auth_time"`
		Email         string          `json:"email"`
		EmailVerified json.RawMessage `json:"email_verified"`
	}
	if err := idt.Claims(&cl); err != nil {
		return refuse("token")
	}
	iat, iatOK := numericDate(cl.IAT)
	authTime, authOK := numericDate(cl.AuthTime)
	var azp *string
	if cl.AZP != nil {
		var a string
		// An explicit null decodes to "", which isn't the client ID.
		if json.Unmarshal(cl.AZP, &a) != nil {
			return refuse("audience")
		}
		azp = &a
	}
	if subtle.ConstantTimeCompare([]byte(cl.Nonce), []byte(st.Nonce)) != 1 {
		return refuse("nonce")
	}
	if azp != nil && *azp != m.clientID || azp == nil && len(idt.Audience) > 1 {
		return refuse("audience")
	}
	if !iatOK || iat.After(in.Now.Add(clockSkew)) {
		return refuse("token")
	}
	if m.twoFactors && (!authOK || in.Now.Sub(authTime) > maxAuthAge || authTime.After(in.Now.Add(clockSkew))) {
		return refuse("token")
	}
	sub := idt.Subject
	if sub == "" || len(sub) > 255 || strings.IndexFunc(sub, unicode.IsControl) >= 0 {
		return refuse("malformed")
	}
	// §5.14.6–5.14.8, the identity.
	verified := string(cl.EmailVerified) == "true"
	email := cl.Email
	if len(email) > 254 || strings.IndexFunc(email, unicode.IsControl) >= 0 {
		email = ""
	}
	if email == "" {
		verified = false
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(&oidcpb.Identity{
		Version: recordVersion, Issuer: m.issuer, Subject: sub, Email: email, EmailVerified: verified,
	})
	if err != nil {
		return auth.MethodResult{}, errRecord
	}
	key := m.identityKey(sub)
	label := email
	if label == "" {
		label = strings.TrimPrefix(m.name, "oidc_")
	}
	address := ""
	if verified {
		address = email
	}
	res := auth.MethodResult{Verified: m.twoFactors, Address: address}
	if in.Purpose == auth.PurposeEnroll {
		res.Credential = &auth.Credential{Key: key, Data: data, Label: label}
		return res, nil
	}
	owner, cred, err := in.Find(key)
	if err != nil {
		return auth.MethodResult{}, err
	}
	if cred == nil {
		res.Unlinked = &auth.Identity{Issuer: m.issuer, Subject: sub, Email: email, EmailVerified: verified}
		res.Credential = &auth.Credential{Key: key, Data: data, Label: label}
		return res, nil
	}
	res.User = owner
	if bytes.Equal(data, cred.Data) {
		data = cred.Data
	}
	res.Credential = &auth.Credential{Key: cred.Key, Data: data, Label: cred.Label}
	return res, nil
}

// isNilConfig reports whether c holds a nil pointer or the like.
func isNilConfig(c Config) bool {
	r := reflect.ValueOf(c)
	switch r.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Chan, reflect.Slice, reflect.Interface:
		return r.IsNil()
	}
	return false
}

// numericDate reads a JWT NumericDate, a JSON number of seconds, whole or
// not (RFC 7519 §2).
func numericDate(n *json.Number) (time.Time, bool) {
	if n == nil {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil || f < 0 || f > 1<<40 {
		return time.Time{}, false
	}
	sec := int64(f)
	return time.Unix(sec, int64((f-float64(sec))*1e9)), true
}
