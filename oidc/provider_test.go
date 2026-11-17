package oidc_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// idp is a provider of the tests' own: discovery, keys, and a token
// endpoint that checks the code, the PKCE verifier and the client.
type idp struct {
	t      *testing.T
	srv    *httptest.Server
	issuer string
	now    func() time.Time

	mu    sync.Mutex
	key   *rsa.PrivateKey
	kid   string
	codes map[string]grant

	// knobs
	docIssuer   string // the issuer discovery names, when set
	tokenURL    string // the token endpoint discovery names, when set
	issParam    bool
	tokenStatus int    // the token endpoint answers this status, when set
	tokenError  string // and this error code
	claims      func(c map[string]any)
	discoveries int
	failDisc    int // discovery fails this many more times
	redirect    bool
	signWith    *rsa.PrivateKey   // signs with this key under the same kid, when set
	ec          *ecdsa.PrivateKey // signs ES256 with this key, published, when set
	keyUse      string            // the published key's use, when set
	jwksStatus  int               // the key set answers this status, when set
	noIDToken   bool
	rawToken    func(payload []byte) string // makes the id_token, when set
	public      bool                        // the client is public: no secret
	sawSecret   bool                        // a request carried a secret
	oddKey      bool                        // the key set holds a key go-jose can't read
}

type grant struct {
	challenge, nonce, sub string
}

const clientID, clientSecret = "shop-client", "shop-secret"

func newIdP(t *testing.T, now func() time.Time) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &idp{t: t, now: now, key: key, kid: "k1", codes: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/jwks", p.jwks)
	mux.HandleFunc("/token", p.token)
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	// http is allowed on localhost alone.
	p.issuer = strings.Replace(p.srv.URL, "127.0.0.1", "localhost", 1)
	return p
}

func (p *idp) discovery(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.discoveries++
	// A redirect to the real document: followed, it would succeed.
	if p.redirect && r.URL.Query().Get("real") == "" {
		w.Header().Set("Location", p.issuer+"/.well-known/openid-configuration?real=1")
		w.WriteHeader(http.StatusFound)
		return
	}
	// A failure with a document that would otherwise do.
	if p.failDisc > 0 {
		p.failDisc--
		w.WriteHeader(http.StatusInternalServerError)
	}
	iss, tok := p.issuer, p.issuer+"/token"
	if p.docIssuer != "" {
		iss = p.docIssuer
	}
	if p.tokenURL != "" {
		tok = p.tokenURL
	}
	json.NewEncoder(w).Encode(map[string]any{
		"issuer": iss, "authorization_endpoint": p.issuer + "/authorize", "token_endpoint": tok,
		"jwks_uri": p.issuer + "/jwks", "authorization_response_iss_parameter_supported": p.issParam,
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (p *idp) jwks(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.jwksStatus != 0 {
		w.WriteHeader(p.jwksStatus)
		return
	}
	use := "sig"
	if p.keyUse != "" {
		use = p.keyUse
	}
	keys := []any{jose.JSONWebKey{Key: &p.key.PublicKey, KeyID: p.kid, Algorithm: "RS256", Use: use}}
	if p.ec != nil {
		keys = append(keys, jose.JSONWebKey{Key: &p.ec.PublicKey, KeyID: "ec1", Algorithm: "ES256", Use: "sig"})
	}
	if p.oddKey {
		// A key of a kind go-jose doesn't read, beside the good ones.
		keys = append([]any{map[string]string{"kty": "OKP", "crv": "X25519", "x": "AAAA", "use": "enc"}}, keys...)
	}
	json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

func (p *idp) token(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tokenStatus != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(p.tokenStatus)
		json.NewEncoder(w).Encode(map[string]string{"error": p.tokenError})
		return
	}
	r.ParseForm()
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
	}
	if ok || r.Form.Has("client_secret") {
		p.sawSecret = true
	}
	if p.public && secret == "" {
		secret = clientSecret
	}
	g, found := p.codes[r.Form.Get("code")]
	delete(p.codes, r.Form.Get("code"))
	sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if id != clientID || secret != clientSecret {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
		return
	}
	if !found || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}
	now := p.now()
	c := map[string]any{
		"iss": p.issuer, "aud": clientID, "sub": g.sub, "nonce": g.nonce,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "auth_time": now.Unix(),
	}
	if p.claims != nil {
		p.claims(c)
	}
	payload, _ := json.Marshal(c)
	if p.noIDToken {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer"})
		return
	}
	if p.rawToken != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": p.rawToken(payload)})
		return
	}
	key := p.key
	if p.signWith != nil {
		key = p.signWith
	}
	sk := jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: p.kid}}
	if p.ec != nil {
		alg := jose.ES256
		if p.ec.Curve.Params().BitSize == 384 {
			alg = jose.ES384
		}
		sk = jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: p.ec, KeyID: "ec1"}}
	}
	signer, err := jose.NewSigner(sk, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		p.t.Error(err)
		return
	}
	jws, _ := signer.Sign(payload)
	raw, _ := jws.CompactSerialize()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": raw})
}

// authorize is the provider's sign-in page: it takes the authorization
// URL, signs sub in, and returns the callback's query.
func (p *idp) authorize(t *testing.T, authURL, sub string) url.Values {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	code := make([]byte, 16)
	rand.Read(code)
	c := base64.RawURLEncoding.EncodeToString(code)
	p.mu.Lock()
	p.codes[c] = grant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), sub: sub}
	p.mu.Unlock()
	out := url.Values{"code": {c}, "state": {q.Get("state")}}
	if p.issParam {
		out.Set("iss", p.issuer)
	}
	return out
}
