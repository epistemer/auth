// Package passkey is auth's passkey method: WebAuthn Level 3, with
// discoverable credentials and user verification (interface §4.11, §5.13,
// ADR 0008).
//
// An app gives the method to auth.WithMethods and names auth.MethodPasskey
// in auth.WithFirst. Challenge returns the options as a json.RawMessage
// that the page passes to PublicKeyCredential.parseCreationOptionsFromJSON
// (in an Enroll) or parseRequestOptionsFromJSON (otherwise); the page posts
// back the credential's toJSON(), which Response wraps:
//
//	pk, err := passkey.New(cfg)
//	a, err := auth.New(db, cfg, dir, mailer,
//		auth.WithMethods(pk),
//		auth.WithFirst(auth.MethodPassword, auth.MethodPasskey),
//	)
//	flow, err := a.SignInWithout(ctx, auth.Cookie())
//	ch, err := a.Challenge(ctx, flow.Token, auth.MethodPasskey) // ch.Options
//	flow, err = a.Prove(ctx, flow.Token, passkey.Response(body))
//
// The module verifies with github.com/go-webauthn/webauthn, whose types
// appear nowhere in its API.
package passkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/epistemer/auth"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"google.golang.org/protobuf/proto"

	"github.com/epistemer/auth/passkey/internal/passkeypb"
)

// Config is what the module reads. An app's generated settings implement
// it when its schema holds authschema.Group(authschema.Passkey()).
type Config interface {
	AuthIssuer() string           // the relying party's name, shown by passkey managers
	AuthPasskeyDomain() string    // the relying party ID: the site's domain
	AuthPasskeyOrigins() []string // the origins a client may report; https://<domain> when empty
}

const (
	maxResponse   = 64 << 10        // §5.13.8
	maxIDLen      = 1023            // a credential ID's longest, WebAuthn §5.8.3
	lifetime      = 5 * time.Minute // options expire (§5.13.8)
	recordVersion = 1
	maxTransports = 8
)

// algorithms are the COSE algorithms offered and accepted, in order of
// preference: ES256, EdDSA, RS256 (§5.13.2).
var algorithms = []int64{-7, -8, -257}

// transports are the ones WebAuthn names; others are dropped (§5.13.8).
var transports = []string{"usb", "nfc", "ble", "smart-card", "hybrid", "internal"}

var b64 = base64.RawURLEncoding

type method struct {
	issuer, domain string
	origins        []string // https:// and http://localhost origins
	opaque         []string // android:apk-key-hash: origins
	rpIDHash       [32]byte
}

// New returns the passkey method, to pass to auth.WithMethods. It refuses
// a nil config, an empty issuer, and a domain that isn't a lowercase DNS
// name of at least two labels (or localhost), with no trailing dot and no
// IP address. Each origin must be exactly https://<host>[:<port>], where
// host is the domain or a name under it, with nothing after: no path, no
// slash, no query, no user. Two exceptions: http://localhost[:<port>] when
// the domain is localhost; and android:apk-key-hash:<43 base64url
// characters>. With the domain localhost the origins are required, since
// the port is the app's.
func New(cfg Config) (auth.Method, error) {
	if cfg == nil {
		return nil, errors.New("passkey: New needs a config")
	}
	m := &method{issuer: cfg.AuthIssuer(), domain: cfg.AuthPasskeyDomain()}
	if m.issuer == "" {
		return nil, errors.New("passkey: auth.issuer is empty")
	}
	if !validDomain(m.domain) {
		return nil, errors.New("passkey: auth.passkey.domain isn't a lowercase DNS name of two labels or more, or localhost")
	}
	origins := cfg.AuthPasskeyOrigins()
	if len(origins) == 0 {
		if m.domain == "localhost" {
			return nil, errors.New("passkey: auth.passkey.origins is required with the domain localhost")
		}
		origins = []string{"https://" + m.domain}
	}
	for _, o := range origins {
		opaque, ok := validOrigin(o, m.domain)
		switch {
		case !ok:
			return nil, errors.New("passkey: an origin in auth.passkey.origins isn't https://<the domain, or a name under it>[:port]")
		case opaque:
			m.opaque = append(m.opaque, o)
		default:
			m.origins = append(m.origins, o)
		}
	}
	m.rpIDHash = sha256.Sum256([]byte(m.domain))
	return m, nil
}

func validDomain(d string) bool {
	if d == "localhost" {
		return true
	}
	// The label rules below refuse capitals and a trailing dot (an empty
	// last label).
	if d == "" || len(d) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	// A last label that reads as a number (10.0.0.300, example.0x1) is no
	// top-level domain, as go-webauthn's own check of an RP ID has it.
	last := labels[len(labels)-1]
	_, err := strconv.ParseUint(last, 0, 64)
	return err != nil && strings.Trim(last, "0123456789") != ""
}

// validOrigin checks one origin against the domain, and reports whether
// it is an opaque (Android app) origin.
func validOrigin(o, domain string) (opaque, ok bool) {
	if h, found := strings.CutPrefix(o, "android:apk-key-hash:"); found {
		raw, err := b64.Strict().DecodeString(h)
		return true, len(h) == 43 && err == nil && len(raw) == 32
	}
	rest, https := strings.CutPrefix(o, "https://")
	if !https {
		if rest, ok = strings.CutPrefix(o, "http://"); !ok {
			return false, false
		}
	}
	// A path, a query or a user is refused below: the host must be the
	// domain or a valid name under it, and the port digits alone.
	host := rest
	if i := strings.LastIndexByte(rest, ':'); i >= 0 {
		host = rest[:i]
		p, err := strconv.Atoi(rest[i+1:])
		if err != nil || p < 1 || p > 65535 || strconv.Itoa(p) != rest[i+1:] {
			return false, false
		}
	}
	// Plain HTTP is for development alone: http://localhost[:port]. The
	// host check below then needs the domain localhost.
	if !https && host != "localhost" {
		return false, false
	}
	if host != domain && !(strings.HasSuffix(host, "."+domain) && validDomain(host)) {
		return false, false
	}
	return false, true
}

// Response is a passkey proof: the JSON of the PublicKeyCredential the
// client returned, as its toJSON() gives it. It is the answer to the
// Challenge of the flow it is proved on, a registration in an Enroll and
// an assertion otherwise.
func Response(credential []byte) auth.Proof { return response{bytes.Clone(credential)} }

type response struct{ b []byte }

func (response) Method() string     { return auth.MethodPasskey }
func (response) String() string     { return "passkey proof" }
func (r response) GoString() string { return r.String() }

func (m *method) Name() string { return auth.MethodPasskey }

// The options' JSON, WebAuthn Level 3's PublicKeyCredentialCreationOptionsJSON
// and PublicKeyCredentialRequestOptionsJSON, unwrapped (§4.11, D30).
type (
	rpEntity struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	userEntity struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	}
	credParam struct {
		Type string `json:"type"`
		Alg  int64  `json:"alg"`
	}
	descriptor struct {
		Type       string   `json:"type"`
		ID         string   `json:"id"`
		Transports []string `json:"transports,omitempty"`
	}
	selection struct {
		ResidentKey        string `json:"residentKey"`
		RequireResidentKey bool   `json:"requireResidentKey"`
		UserVerification   string `json:"userVerification"`
	}
	creationOptions struct {
		RP                     rpEntity     `json:"rp"`
		User                   userEntity   `json:"user"`
		Challenge              string       `json:"challenge"`
		PubKeyCredParams       []credParam  `json:"pubKeyCredParams"`
		Timeout                int64        `json:"timeout"`
		ExcludeCredentials     []descriptor `json:"excludeCredentials"`
		AuthenticatorSelection selection    `json:"authenticatorSelection"`
		Attestation            string       `json:"attestation"`
	}
	requestOptions struct {
		Challenge        string       `json:"challenge"`
		Timeout          int64        `json:"timeout"`
		RPID             string       `json:"rpId"`
		AllowCredentials []descriptor `json:"allowCredentials"`
		UserVerification string       `json:"userVerification"`
	}
)

// Errors of the module's own: fixed texts, never a library's (§4.9).
var (
	errNoName      = errors.New("passkey: the user has no name to register a passkey under")
	errState       = errors.New("passkey: the flow's state can't be read")
	errRecord      = errors.New("passkey: a stored passkey can't be read")
	errUnsupported = errors.New("passkey: the options can't be encoded")
	errUserID      = errors.New("passkey: a user handle must be 1 to 64 bytes")
)

// Start makes a challenge and the options for it (§5.13.2, §5.13.3). Before
// a sessionless flow's first proof the engine tells it no user, and the
// options name no credential, whoever the login (§4.9).
func (m *method) Start(_ context.Context, in auth.MethodInput) (any, []byte, error) {
	ch := make([]byte, 32)
	rand.Read(ch)
	st := &passkeypb.State{Version: recordVersion, Challenge: ch, Expires: in.Now.Add(lifetime).UnixNano()}
	var opts any
	if in.Purpose == auth.PurposeEnroll {
		if in.User == nil || in.User.Name == "" {
			return nil, nil, errNoName
		}
		if len(in.User.ID) == 0 || len(in.User.ID) > 64 {
			return nil, nil, errUserID
		}
		st.Create, st.UserId = true, string(in.User.ID)
		params := make([]credParam, len(algorithms))
		for i, a := range algorithms {
			params[i] = credParam{"public-key", a}
		}
		exclude, err := descriptors(in.Credentials)
		if err != nil {
			return nil, nil, err
		}
		opts = creationOptions{
			RP:                 rpEntity{m.domain, m.issuer},
			User:               userEntity{b64.EncodeToString([]byte(in.User.ID)), in.User.Name, in.User.Name},
			Challenge:          b64.EncodeToString(ch),
			PubKeyCredParams:   params,
			Timeout:            lifetime.Milliseconds(),
			ExcludeCredentials: exclude,
			AuthenticatorSelection: selection{
				ResidentKey: "required", RequireResidentKey: true, UserVerification: "required",
			},
			Attestation: "none",
		}
	} else {
		allow := []descriptor{}
		if in.User != nil {
			// The options are for this user: a passkey of anyone else's is
			// refused, also when they hold none (review 0022).
			var err error
			if allow, err = descriptors(in.Credentials); err != nil {
				return nil, nil, err
			}
			st.UserId = string(in.User.ID)
		}
		opts = requestOptions{
			Challenge: b64.EncodeToString(ch), Timeout: lifetime.Milliseconds(), RPID: m.domain,
			AllowCredentials: allow, UserVerification: "required",
		}
	}
	j, err := json.Marshal(opts)
	if err != nil {
		return nil, nil, errUnsupported
	}
	state, err := proto.Marshal(st)
	if err != nil {
		return nil, nil, errState
	}
	return json.RawMessage(j), state, nil
}

func descriptors(cs []auth.Credential) ([]descriptor, error) {
	out := make([]descriptor, 0, len(cs))
	for _, c := range cs {
		var rec passkeypb.Credential
		if err := proto.Unmarshal(c.Data, &rec); err != nil || rec.Version != recordVersion {
			return nil, errRecord
		}
		out = append(out, descriptor{Type: "public-key", ID: b64.EncodeToString(c.Key), Transports: rec.Transports})
	}
	return out, nil
}

// Verify checks a response against the flow's state (§5.13). A refusal is
// auth.Refuse with one of §5.13.13's reasons; no error of the library's
// reaches what it returns.
func (m *method) Verify(_ context.Context, in auth.MethodInput, state []byte, p auth.Proof) (auth.MethodResult, error) {
	r, ok := p.(response)
	if !ok || len(r.b) > maxResponse {
		return auth.MethodResult{}, auth.Refuse("malformed")
	}
	var st passkeypb.State
	if err := proto.Unmarshal(state, &st); err != nil || st.Version != recordVersion {
		return auth.MethodResult{}, errState
	}
	if st.Create != (in.Purpose == auth.PurposeEnroll) {
		return auth.MethodResult{}, errState
	}
	if !in.Now.Before(time.Unix(0, st.Expires)) {
		return auth.MethodResult{}, auth.Refuse("expired")
	}
	if st.Create {
		return m.register(in, &st, r.b)
	}
	return m.assert(in, &st, r.b)
}

// checkClient checks the client data a ceremony signed: the challenge, the
// origin, and that it wasn't cross-origin (§5.13.1).
func (m *method) checkClient(cd protocol.CollectedClientData, st *passkeypb.State) string {
	if subtle.ConstantTimeCompare([]byte(cd.Challenge), []byte(b64.EncodeToString(st.Challenge))) != 1 {
		return "challenge"
	}
	if !slices.Contains(m.origins, cd.Origin) && !slices.Contains(m.opaque, cd.Origin) {
		return "origin"
	}
	if cd.CrossOrigin || cd.TopOrigin != "" {
		return "cross_origin"
	}
	return ""
}

// checkAuthenticator checks the authenticator data: the relying party, the
// UP and UV flags (§5.13.5), and backup state without eligibility
// (§5.13.7).
func (m *method) checkAuthenticator(ad protocol.AuthenticatorData) string {
	switch {
	case subtle.ConstantTimeCompare(ad.RPIDHash, m.rpIDHash[:]) != 1:
		return "rp"
	case !ad.Flags.HasUserPresent() || !ad.Flags.HasUserVerified():
		return "flags"
	case ad.Flags.HasBackupState() && !ad.Flags.HasBackupEligible():
		return "backup_flags"
	}
	return ""
}

func (m *method) register(in auth.MethodInput, st *passkeypb.State, b []byte) (auth.MethodResult, error) {
	refuse := func(reason string) (auth.MethodResult, error) { return auth.MethodResult{}, auth.Refuse(reason) }
	if in.User == nil || string(in.User.ID) != st.UserId {
		return auth.MethodResult{}, errState
	}
	pcc, err := protocol.ParseCredentialCreationResponseBytes(b)
	if err != nil || len(pcc.RawID) == 0 || len(pcc.RawID) > maxIDLen ||
		pcc.Response.CollectedClientData.Type != protocol.CreateCeremony ||
		!bytes.Equal(pcc.RawID, pcc.Response.AttestationObject.AuthData.AttData.CredentialID) {
		return refuse("malformed")
	}
	if reason := m.checkClient(pcc.Response.CollectedClientData, st); reason != "" {
		return refuse(reason)
	}
	ad := pcc.Response.AttestationObject.AuthData
	if reason := m.checkAuthenticator(ad); reason != "" {
		return refuse(reason)
	}
	var pk webauthncose.PublicKeyData
	if err := webauthncbor.Unmarshal(ad.AttData.CredentialPublicKey, &pk); err != nil || pk.Algorithm == 0 {
		return refuse("malformed")
	}
	if !slices.Contains(algorithms, pk.Algorithm) {
		return refuse("algorithm")
	}
	// With attestation none the library never parses the key: a key that
	// can't verify would be enrolled as a factor (review 0022).
	if !usableKey(ad.AttData.CredentialPublicKey, pk.Algorithm) {
		return refuse("malformed")
	}
	params := make([]protocol.CredentialParameter, len(algorithms))
	for i, a := range algorithms {
		params[i] = protocol.CredentialParameter{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.COSEAlgorithmIdentifier(a)}
	}
	if _, err := pcc.Verify(b64.EncodeToString(st.Challenge), m.domain, m.origins, m.opaque, nil,
		protocol.TopOriginExplicitVerificationMode, false, true, true, nil, params,
		protocol.AttestationPolicy{}, protocol.SignaturePolicy{}); err != nil {
		return refuse("attestation")
	}
	var ts []string
	for _, t := range pcc.Raw.AttestationResponse.Transports {
		if slices.Contains(transports, t) && !slices.Contains(ts, t) && len(ts) < maxTransports {
			ts = append(ts, t)
		}
	}
	data, err := proto.Marshal(&passkeypb.Credential{
		Version: recordVersion, PublicKey: ad.AttData.CredentialPublicKey, Algorithm: pk.Algorithm,
		Counter: ad.Counter, BackupEligible: ad.Flags.HasBackupEligible(), BackupState: ad.Flags.HasBackupState(),
		Transports: ts, Aaguid: ad.AttData.AAGUID, AttestationFormat: pcc.Response.AttestationObject.Format,
	})
	if err != nil {
		return auth.MethodResult{}, errRecord
	}
	return auth.MethodResult{Credential: &auth.Credential{Key: bytes.Clone(pcc.RawID), Data: data}, Verified: true}, nil
}

// usableKey parses a COSE key: the library checks that an EC2 or OKP key
// is of the kind its algorithm names, on its curve and of its length; an
// RSA key it checks for neither, so that is done here, with at least 2048
// bits and an odd exponent of 3 or more.
func usableKey(cose []byte, alg int64) bool {
	key, err := webauthncose.ParsePublicKey(cose)
	if err != nil {
		return false
	}
	switch k := key.(type) {
	case webauthncose.EC2PublicKeyData, webauthncose.OKPPublicKeyData:
		return true
	case webauthncose.RSAPublicKeyData:
		e, err := webauthncose.ParseRSAPublicKeyDataExponent(&k)
		n := new(big.Int).SetBytes(k.Modulus)
		// crypto/rsa verifies with no exponent over 2³¹-1.
		return alg == -257 && err == nil && e >= 3 && e <= math.MaxInt32 && e%2 == 1 && n.BitLen() >= 2048
	}
	return false
}

func (m *method) assert(in auth.MethodInput, st *passkeypb.State, b []byte) (auth.MethodResult, error) {
	refuse := func(reason string) (auth.MethodResult, error) { return auth.MethodResult{}, auth.Refuse(reason) }
	par, err := protocol.ParseCredentialRequestResponseBytes(b)
	if err != nil || len(par.RawID) == 0 || len(par.RawID) > maxIDLen ||
		par.Response.CollectedClientData.Type != protocol.AssertCeremony {
		return refuse("malformed")
	}
	if reason := m.checkClient(par.Response.CollectedClientData, st); reason != "" {
		return refuse(reason)
	}
	ad := par.Response.AuthenticatorData
	if reason := m.checkAuthenticator(ad); reason != "" {
		return refuse(reason)
	}
	// Found by its ID, never by the user handle (§5.13.4).
	owner, c, err := in.Find(par.RawID)
	if err != nil {
		return auth.MethodResult{}, err
	}
	if c == nil || st.UserId != "" && string(owner) != st.UserId {
		return refuse("unknown_credential")
	}
	uh := par.Response.UserHandle
	if st.UserId == "" && len(uh) == 0 || len(uh) > 0 && !bytes.Equal(uh, []byte(owner)) {
		return refuse("user_handle")
	}
	var rec passkeypb.Credential
	if err := proto.Unmarshal(c.Data, &rec); err != nil || rec.Version != recordVersion || !slices.Contains(algorithms, rec.Algorithm) {
		return auth.MethodResult{}, errRecord
	}
	if rec.BackupEligible != ad.Flags.HasBackupEligible() {
		return refuse("backup_flags")
	}
	if err := par.Verify(b64.EncodeToString(st.Challenge), m.domain, "", m.origins, m.opaque, nil,
		protocol.TopOriginExplicitVerificationMode, false, true, true, rec.PublicKey, protocol.SignaturePolicy{}); err != nil {
		return refuse("signature")
	}
	// WebAuthn §7.2: either above zero, the presented must be greater
	// (§5.13.6).
	if (rec.Counter > 0 || ad.Counter > 0) && ad.Counter <= rec.Counter {
		return refuse("counter")
	}
	rec.Counter, rec.BackupState = ad.Counter, ad.Flags.HasBackupState()
	data, err := proto.Marshal(&rec)
	if err != nil {
		return auth.MethodResult{}, errRecord
	}
	return auth.MethodResult{
		User: owner, Credential: &auth.Credential{Key: bytes.Clone(c.Key), Data: data, Label: c.Label}, Verified: true,
	}, nil
}
