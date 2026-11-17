package shop_test

import (
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

// idp is a provider for the shop's tests: discovery, keys, a sign-in page
// that signs in at once and redirects back, and a token endpoint that
// checks the code and its PKCE verifier.
type idp struct {
	srv    *httptest.Server
	issuer string
	now    func() time.Time
	key    *rsa.PrivateKey

	mu       sync.Mutex
	codes    map[string][2]string // code -> challenge, nonce
	sub      string
	email    string
	badState bool
}

const idpClient, idpSecret = "shop", "shop-secret"

func newIdP(t *testing.T, now func() time.Time) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &idp{now: now, key: key, codes: map[string][2]string{}, sub: "nina"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.issuer, "authorization_endpoint": p.issuer + "/authorize",
			"token_endpoint": p.issuer + "/token", "jwks_uri": p.issuer + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", p.authorize)
	mux.HandleFunc("/token", p.token)
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	p.issuer = strings.Replace(p.srv.URL, "127.0.0.1", "localhost", 1)
	return p
}

func (p *idp) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	b := make([]byte, 16)
	rand.Read(b)
	code := base64.RawURLEncoding.EncodeToString(b)
	p.mu.Lock()
	p.codes[code] = [2]string{q.Get("code_challenge"), q.Get("nonce")}
	state := q.Get("state")
	if p.badState {
		state = "another"
	}
	p.mu.Unlock()
	back := q.Get("redirect_uri") + "?" + url.Values{"code": {code}, "state": {state}}.Encode()
	http.Redirect(w, r, back, http.StatusFound)
}

func (p *idp) token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	id, secret, _ := r.BasicAuth()
	p.mu.Lock()
	g, ok := p.codes[r.Form.Get("code")]
	delete(p.codes, r.Form.Get("code"))
	sub, email := p.sub, p.email
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	w.Header().Set("Content-Type", "application/json")
	if !ok || id != idpClient || secret != idpSecret || base64.RawURLEncoding.EncodeToString(sum[:]) != g[0] {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}
	now := p.now()
	payload, _ := json.Marshal(map[string]any{
		"iss": p.issuer, "aud": idpClient, "sub": sub, "nonce": g[1], "email": email, "email_verified": true,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	})
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: p.key, KeyID: "k"}}, nil)
	jws, _ := signer.Sign(payload)
	raw, _ := jws.CompactSerialize()
	json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": raw})
}
