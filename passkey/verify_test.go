package passkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/epistemer/auth"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"google.golang.org/protobuf/proto"

	"github.com/epistemer/auth/passkey/internal/passkeypb"
	"github.com/epistemer/auth/passkey/internal/softauth"
)

// The rules of §5.13, against Start and Verify directly, with a store of
// credentials in memory standing in for the engine's.

const origin = "https://toyshop.example"

type config struct {
	issuer, domain string
	origins        []string
}

func (c config) AuthIssuer() string           { return c.issuer }
func (c config) AuthPasskeyDomain() string    { return c.domain }
func (c config) AuthPasskeyOrigins() []string { return c.origins }

func newMethod(t *testing.T) *method {
	t.Helper()
	m, err := New(config{"Toy Shop", "toyshop.example", nil})
	if err != nil {
		t.Fatal(err)
	}
	return m.(*method)
}

type held struct {
	owner auth.UserID
	c     auth.Credential
}

// world is the engine as Verify sees it: credentials by key, and a clock.
type world struct {
	t     *testing.T
	m     *method
	creds map[string]held
	now   time.Time
}

func newWorld(t *testing.T) *world {
	return &world{t: t, m: newMethod(t), creds: map[string]held{}, now: time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)}
}

var sara = &auth.User{ID: "u1", Name: "sara"}

func (w *world) input(p auth.Purpose, u *auth.User) auth.MethodInput {
	in := auth.MethodInput{Purpose: p, User: u, Now: w.now}
	if u != nil {
		for _, h := range w.creds {
			if h.owner == u.ID {
				in.Credentials = append(in.Credentials, h.c)
			}
		}
	}
	in.Find = func(key []byte) (auth.UserID, *auth.Credential, error) {
		h, ok := w.creds[string(key)]
		if !ok {
			return "", nil, nil
		}
		c := h.c
		return h.owner, &c, nil
	}
	return in
}

func (w *world) start(in auth.MethodInput) (json.RawMessage, []byte) {
	w.t.Helper()
	out, state, err := w.m.Start(context.Background(), in)
	if err != nil {
		w.t.Fatal(err)
	}
	return out.(json.RawMessage), state
}

// enroll registers a's passkey for sara and stores it.
func (w *world) enroll(a *softauth.Authenticator) {
	w.t.Helper()
	in := w.input(auth.PurposeEnroll, sara)
	opts, state := w.start(in)
	b, err := a.Create(opts)
	if err != nil {
		w.t.Fatal(err)
	}
	res, err := w.m.Verify(context.Background(), in, state, Response(b))
	if err != nil {
		w.t.Fatalf("register: %v", err)
	}
	if res.Credential == nil || !bytes.Equal(res.Credential.Key, a.ID) {
		w.t.Fatalf("register: %+v", res)
	}
	w.creds[string(a.ID)] = held{sara.ID, *res.Credential}
}

// signIn asserts with a, as a discoverable sign-in (no user) or for u.
func (w *world) signIn(a *softauth.Authenticator, u *auth.User) (auth.MethodResult, error) {
	w.t.Helper()
	in := w.input(auth.PurposeSignIn, u)
	opts, state := w.start(in)
	b, err := a.Get(opts)
	if err != nil {
		w.t.Fatal(err)
	}
	res, err := w.m.Verify(context.Background(), in, state, Response(b))
	if err == nil {
		h := w.creds[string(res.Credential.Key)]
		h.c = *res.Credential
		w.creds[string(res.Credential.Key)] = h
	}
	return res, err
}

func record(t *testing.T, c auth.Credential) *passkeypb.Credential {
	t.Helper()
	var r passkeypb.Credential
	if err := proto.Unmarshal(c.Data, &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

func wantRefused(t *testing.T, name string, err error, reason string) {
	t.Helper()
	if !errors.Is(err, auth.Refuse(reason)) {
		t.Errorf("%s: %v, want the reason %q", name, err, reason)
	}
}

// §5.13.2, §5.13.10: ES256, EdDSA and RS256 each register and sign in; the
// record holds the key, the algorithm, the counter, the flags, the
// transports, the AAGUID and the format; every proof is Verified.
func TestAlgorithms(t *testing.T) {
	for _, alg := range []int64{softauth.ES256, softauth.EdDSA, softauth.RS256} {
		w := newWorld(t)
		a := softauth.New(origin)
		a.Alg, a.BE, a.BS = alg, true, true
		w.enroll(a)
		r := record(t, w.creds[string(a.ID)].c)
		if r.Algorithm != alg || r.Version != recordVersion || len(r.PublicKey) == 0 || !r.BackupEligible || !r.BackupState ||
			r.AttestationFormat != "none" || len(r.Aaguid) != 16 || strings.Join(r.Transports, ",") != "internal,hybrid" {
			t.Errorf("%d: record %+v", alg, r)
		}
		res, err := w.signIn(a, nil)
		if err != nil || res.User != "u1" || !res.Verified || !bytes.Equal(res.Credential.Key, a.ID) {
			t.Errorf("%d: sign-in %+v %v", alg, res, err)
		}
	}
}

// §5.13.2, D30: the creation options ask for a discoverable credential,
// user verification and attestation none, offer the three algorithms in
// order, name the user by the UserID, and exclude the user's passkeys.
func TestCreationOptions(t *testing.T) {
	w := newWorld(t)
	held := softauth.New(origin)
	w.enroll(held)
	opts, _ := w.start(w.input(auth.PurposeEnroll, sara))
	var o creationOptions
	if err := json.Unmarshal(opts, &o); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(opts, []byte(`"publicKey"`)) {
		t.Error("options wrapped in publicKey")
	}
	sel := o.AuthenticatorSelection
	if o.RP != (rpEntity{"toyshop.example", "Toy Shop"}) || o.User != (userEntity{"dTE", "sara", "sara"}) ||
		sel.ResidentKey != "required" || !sel.RequireResidentKey || sel.UserVerification != "required" ||
		o.Attestation != "none" || o.Timeout != 300000 || len(o.Challenge) != 43 {
		t.Errorf("options: %s", opts)
	}
	if len(o.PubKeyCredParams) != 3 || o.PubKeyCredParams[0].Alg != -7 || o.PubKeyCredParams[1].Alg != -8 || o.PubKeyCredParams[2].Alg != -257 {
		t.Errorf("algorithms: %+v", o.PubKeyCredParams)
	}
	if len(o.ExcludeCredentials) != 1 || o.ExcludeCredentials[0].ID != b64.EncodeToString(held.ID) ||
		strings.Join(o.ExcludeCredentials[0].Transports, ",") != "internal,hybrid" || o.ExcludeCredentials[0].Type != "public-key" {
		t.Errorf("exclude: %+v", o.ExcludeCredentials)
	}
	if _, _, err := w.m.Start(context.Background(), w.input(auth.PurposeEnroll, &auth.User{ID: "u2"})); err == nil {
		t.Error("an empty name: no error")
	}
}

// §5.13.3, §5.1.3: with no user the request options name no credential and
// differ between calls only in their challenge; with the user, they list
// the user's passkeys and their transports.
func TestRequestOptions(t *testing.T) {
	w := newWorld(t)
	w.enroll(softauth.New(origin))
	strip := func(b json.RawMessage) string {
		var o requestOptions
		if err := json.Unmarshal(b, &o); err != nil {
			t.Fatal(err)
		}
		o.Challenge = ""
		j, _ := json.Marshal(o)
		return string(j)
	}
	a, _ := w.start(w.input(auth.PurposeSignIn, nil))
	b, _ := w.start(w.input(auth.PurposeRecover, nil))
	if strip(a) != strip(b) || bytes.Equal(a, b) || !strings.Contains(string(a), `"allowCredentials":[]`) || !strings.Contains(string(a), `"userVerification":"required"`) {
		t.Errorf("no user: %s / %s", a, b)
	}
	c, _ := w.start(w.input(auth.PurposeStepUp, sara))
	var o requestOptions
	json.Unmarshal(c, &o)
	if len(o.AllowCredentials) != 1 || o.RPID != "toyshop.example" || len(o.AllowCredentials[0].Transports) != 2 {
		t.Errorf("with the user: %s", c)
	}
}

// §5.13.1–8, §5.13.13: each refusal of an assertion, with its reason.
func TestAssertionRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		knob   func(a *softauth.Authenticator)
		user   *auth.User
		reason string
	}{
		"no UV":                {func(a *softauth.Authenticator) { a.NoUV = true }, nil, "flags"},
		"no UP":                {func(a *softauth.Authenticator) { a.NoUP = true }, nil, "flags"},
		"another origin":       {func(a *softauth.Authenticator) { a.Origin = "https://evil.example" }, nil, "origin"},
		"a subdomain":          {func(a *softauth.Authenticator) { a.Origin = "https://shop.toyshop.example" }, nil, "origin"},
		"another rp":           {func(a *softauth.Authenticator) { a.RPID = "evil.example" }, nil, "rp"},
		"cross-origin":         {func(a *softauth.Authenticator) { a.CrossOrigin = true }, nil, "cross_origin"},
		"top origin":           {func(a *softauth.Authenticator) { a.CrossOrigin, a.TopOrigin = true, origin }, nil, "cross_origin"},
		"top origin alone":     {func(a *softauth.Authenticator) { a.TopOrigin = origin }, nil, "cross_origin"},
		"a create's type":      {func(a *softauth.Authenticator) { a.Type = "webauthn.create" }, nil, "malformed"},
		"another challenge":    {func(a *softauth.Authenticator) { a.Challenge = "AAAA" }, nil, "challenge"},
		"BE changed":           {func(a *softauth.Authenticator) { a.BE = true }, nil, "backup_flags"},
		"BS without BE":        {func(a *softauth.Authenticator) { a.BS = true }, nil, "backup_flags"},
		"no handle":            {func(a *softauth.Authenticator) { a.NoHandle = true }, nil, "user_handle"},
		"another handle":       {func(a *softauth.Authenticator) { a.Handle = []byte("u2") }, nil, "user_handle"},
		"another handle, user": {func(a *softauth.Authenticator) { a.Handle = []byte("u2") }, sara, "user_handle"},
		"counter replayed":     {func(a *softauth.Authenticator) { a.Counter, a.NoStep = 1, true }, nil, "counter"},
		"zero against ten":     {func(a *softauth.Authenticator) { a.Counter, a.NoStep = 0, true }, nil, "counter"},
		"an ID of 1024":        {func(a *softauth.Authenticator) { a.ID = bytes.Repeat([]byte{1}, 1024) }, nil, "malformed"},
		"an unknown ID":        {func(a *softauth.Authenticator) { a.ID = []byte("unknown") }, nil, "unknown_credential"},
		"another user's ID":    {func(a *softauth.Authenticator) {}, &auth.User{ID: "u2", Name: "omar"}, "unknown_credential"},
	} {
		w := newWorld(t)
		a := softauth.New(origin)
		w.enroll(a)
		// Ten sign-ins, so the counter is ten.
		for range 10 {
			if _, err := w.signIn(a, nil); err != nil {
				t.Fatal(err)
			}
		}
		u := tc.user
		if u != nil && u.ID == "u2" {
			// omar holds a passkey of his own, which the options name.
			b := softauth.New(origin)
			in := w.input(auth.PurposeEnroll, u)
			opts, state := w.start(in)
			resp, _ := b.Create(opts)
			res, err := w.m.Verify(context.Background(), in, state, Response(resp))
			if err != nil {
				t.Fatal(err)
			}
			w.creds[string(b.ID)] = held{u.ID, *res.Credential}
		}
		tc.knob(a)
		before := w.creds[string(a.ID)]
		_, err := w.signIn(a, u)
		wantRefused(t, name, err, tc.reason)
		if after := w.creds[string(a.ID)]; !bytes.Equal(after.c.Data, before.c.Data) {
			t.Errorf("%s: the record changed", name)
		}
	}
}

// §5.13.2, §5.13.13: each refusal of a registration, with its reason.
func TestRegistrationRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		knob   func(a *softauth.Authenticator)
		reason string
	}{
		"no UV":             {func(a *softauth.Authenticator) { a.NoUV = true }, "flags"},
		"another origin":    {func(a *softauth.Authenticator) { a.Origin = "https://evil.example" }, "origin"},
		"another rp":        {func(a *softauth.Authenticator) { a.RPID = "evil.example" }, "rp"},
		"cross-origin":      {func(a *softauth.Authenticator) { a.CrossOrigin = true }, "cross_origin"},
		"a get's type":      {func(a *softauth.Authenticator) { a.Type = "webauthn.get" }, "malformed"},
		"another challenge": {func(a *softauth.Authenticator) { a.Challenge = "AAAA" }, "challenge"},
		"BS without BE":     {func(a *softauth.Authenticator) { a.BS = true }, "backup_flags"},
		"ES384":             {func(a *softauth.Authenticator) { a.Alg = softauth.ES384 }, "algorithm"},
		"an ID of 1024":     {func(a *softauth.Authenticator) { a.ID = bytes.Repeat([]byte{1}, 1024) }, "malformed"},
		"bad attestation":   {func(a *softauth.Authenticator) { a.Format = "packed" }, "attestation"},
	} {
		w := newWorld(t)
		a := softauth.New(origin)
		tc.knob(a)
		in := w.input(auth.PurposeEnroll, sara)
		opts, state := w.start(in)
		b, err := a.Create(opts)
		if err != nil {
			t.Fatal(err)
		}
		_, err = w.m.Verify(context.Background(), in, state, Response(b))
		wantRefused(t, name, err, tc.reason)
	}
}

// §5.13.8: a response over 64 KiB is refused before it is parsed; one that
// doesn't parse, an empty ID, and a ceremony of the wrong kind are
// malformed; options expire five minutes after Start.
func TestLimits(t *testing.T) {
	w := newWorld(t)
	a := softauth.New(origin)
	w.enroll(a)
	in := w.input(auth.PurposeSignIn, nil)
	opts, state := w.start(in)
	good, _ := a.Get(opts)
	padded := append(bytes.TrimSuffix(good, []byte("}")), []byte(`,"pad":"`+strings.Repeat("a", maxResponse)+`"}`)...)
	_, err := w.m.Verify(context.Background(), in, state, Response(padded))
	wantRefused(t, "over 64 KiB", err, "malformed")
	_, err = w.m.Verify(context.Background(), in, state, Response([]byte("{")))
	wantRefused(t, "not JSON", err, "malformed")
	var j map[string]any
	json.Unmarshal(good, &j)
	j["id"], j["rawId"] = "", ""
	empty, _ := json.Marshal(j)
	_, err = w.m.Verify(context.Background(), in, state, Response(empty))
	wantRefused(t, "an empty ID", err, "malformed")
	// A registration sent to an assertion, and back.
	enrollIn := w.input(auth.PurposeEnroll, sara)
	eopts, estate := w.start(enrollIn)
	created, _ := softauth.New(origin).Create(eopts)
	_, err = w.m.Verify(context.Background(), in, state, Response(created))
	wantRefused(t, "a registration to an assertion", err, "malformed")
	_, err = w.m.Verify(context.Background(), enrollIn, estate, Response(good))
	wantRefused(t, "an assertion to a registration", err, "malformed")
	// Five minutes.
	late := in
	late.Now = w.now.Add(lifetime)
	_, err = w.m.Verify(context.Background(), late, state, Response(good))
	wantRefused(t, "expired", err, "expired")
	late.Now = late.Now.Add(-time.Nanosecond)
	if _, err := w.m.Verify(context.Background(), late, state, Response(good)); err != nil {
		t.Errorf("just in time: %v", err)
	}
	// A state of another version is the method's own failure.
	bad, _ := proto.Marshal(&passkeypb.State{Version: recordVersion + 1, Challenge: []byte("x"), Expires: w.now.Add(time.Hour).UnixNano()})
	if _, err := w.m.Verify(context.Background(), in, bad, Response(good)); err == nil || errors.Is(err, auth.ErrBadCredentials) {
		t.Errorf("another state version: %v", err)
	}
	// Another proof type.
	_, err = w.m.Verify(context.Background(), in, state, auth.Password("x"))
	wantRefused(t, "a password", err, "malformed")
}

// §5.13.6, §5.13.7: two zeros pass every time; a greater counter is stored;
// backup state is stored as last seen.
func TestCountersAndBackup(t *testing.T) {
	w := newWorld(t)
	synced := softauth.New(origin)
	synced.NoStep, synced.BE = true, true
	w.enroll(synced)
	for range 3 {
		if _, err := w.signIn(synced, nil); err != nil {
			t.Fatalf("two zeros: %v", err)
		}
	}
	synced.BS = true
	if _, err := w.signIn(synced, nil); err != nil {
		t.Fatal(err)
	}
	if r := record(t, w.creds[string(synced.ID)].c); r.Counter != 0 || !r.BackupState {
		t.Errorf("synced record: %+v", r)
	}
	bound := softauth.New(origin)
	bound.Step = 5
	w.enroll(bound)
	if _, err := w.signIn(bound, nil); err != nil {
		t.Fatal(err)
	}
	if r := record(t, w.creds[string(bound.ID)].c); r.Counter != 5 {
		t.Errorf("counter %d", r.Counter)
	}
	// A clone that ran behind: refused, and the stored counter kept.
	bound.Counter, bound.Step = 2, 1
	_, err := w.signIn(bound, nil)
	wantRefused(t, "behind", err, "counter")
	if r := record(t, w.creds[string(bound.ID)].c); r.Counter != 5 {
		t.Errorf("counter after a refusal %d", r.Counter)
	}
}

// §5.13.4: the signature is checked with the stored key: an authenticator
// with the same ID and handle but another key is refused.
func TestSignature(t *testing.T) {
	w := newWorld(t)
	a := softauth.New(origin)
	w.enroll(a)
	thief := softauth.New(origin)
	thief.ID = a.ID
	if _, err := thief.Create(json.RawMessage(`{"rp":{"id":"toyshop.example"},"user":{"id":"dTE"},"challenge":"AAAA"}`)); err != nil {
		t.Fatal(err)
	}
	thief.Counter = 100
	_, err := w.signIn(thief, nil)
	wantRefused(t, "another key", err, "signature")
}

// §5.13.11, D43: the method counts by address alone.
func TestAddressOnly(t *testing.T) {
	if ao, ok := any(newMethod(t)).(auth.AddressOnly); !ok || !ao.AddressOnly() {
		t.Error("not AddressOnly")
	}
}

// §4.11: New refuses each bad config.
func TestNew(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("nil: accepted")
	}
	var typedNil *config
	if _, err := New(typedNil); err == nil {
		t.Error("a typed nil: accepted")
	}
	bad := map[string]config{
		"no issuer":        {"", "toyshop.example", nil},
		"capitals":         {"Toy", "Toyshop.example", nil},
		"trailing dot":     {"Toy", "toyshop.example.", nil},
		"one label":        {"Toy", "toyshop", nil},
		"empty":            {"Toy", "", nil},
		"an IP":            {"Toy", "192.0.2.1", nil},
		"an IPv6":          {"Toy", "::1", nil},
		"underscore":       {"Toy", "toy_shop.example", nil},
		"dash first":       {"Toy", "-toy.example", nil},
		"digits last":      {"Toy", "toyshop.123", nil},
		"localhost alone":  {"Toy", "localhost", nil},
		"http":             {"Toy", "toyshop.example", []string{"http://toyshop.example"}},
		"another site":     {"Toy", "toyshop.example", []string{"https://evil.example"}},
		"a suffix":         {"Toy", "toyshop.example", []string{"https://xtoyshop.example"}},
		"a slash":          {"Toy", "toyshop.example", []string{"https://toyshop.example/"}},
		"a path":           {"Toy", "toyshop.example", []string{"https://toyshop.example/app"}},
		"a query":          {"Toy", "toyshop.example", []string{"https://toyshop.example?x"}},
		"a user":           {"Toy", "toyshop.example", []string{"https://u@toyshop.example"}},
		"port 0":           {"Toy", "toyshop.example", []string{"https://toyshop.example:0"}},
		"port too big":     {"Toy", "toyshop.example", []string{"https://toyshop.example:65536"}},
		"port leading 0":   {"Toy", "toyshop.example", []string{"https://toyshop.example:0443"}},
		"empty port":       {"Toy", "toyshop.example", []string{"https://toyshop.example:"}},
		"http not local":   {"Toy", "localhost", []string{"http://toyshop.example"}},
		"http under local": {"Toy", "localhost", []string{"http://shop.localhost:8080"}},
		"http, not local":  {"Toy", "toyshop.example", []string{"http://localhost"}},
		"a fragment":       {"Toy", "toyshop.example", []string{"https://toyshop.example#x"}},
		"a space":          {"Toy", "toyshop.example", []string{"https://toyshop.example "}},
		"path with port":   {"Toy", "toyshop.example", []string{"https://toyshop.example:443/x"}},
		"short apk hash":   {"Toy", "toyshop.example", []string{"android:apk-key-hash:abc"}},
		"capital host":     {"Toy", "toyshop.example", []string{"https://Shop.toyshop.example"}},
		"empty origin":     {"Toy", "toyshop.example", []string{""}},
	}
	for name, c := range bad {
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	good := map[string]config{
		"default":     {"Toy", "toyshop.example", nil},
		"a port":      {"Toy", "toyshop.example", []string{"https://toyshop.example:8443"}},
		"a subdomain": {"Toy", "toyshop.example", []string{"https://shop.toyshop.example"}},
		"localhost":   {"Toy", "localhost", []string{"http://localhost:8080", "https://localhost"}},
		"android":     {"Toy", "toyshop.example", []string{"https://toyshop.example", "android:apk-key-hash:" + strings.Repeat("A", 43)}},
	}
	for name, c := range good {
		if _, err := New(c); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// §5.13.1: a configured origin other than the domain's is accepted, and an
// Android app's origin is matched as itself.
func TestOrigins(t *testing.T) {
	apk := "android:apk-key-hash:" + strings.Repeat("A", 43)
	m, err := New(config{"Toy", "toyshop.example", []string{"https://shop.toyshop.example:8443", apk}})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range []string{"https://shop.toyshop.example:8443", apk} {
		w := newWorld(t)
		w.m = m.(*method)
		a := softauth.New(o)
		w.enroll(a)
		if _, err := w.signIn(a, nil); err != nil {
			t.Errorf("%s: %v", o, err)
		}
	}
	w := newWorld(t)
	w.m = m.(*method)
	a := softauth.New("https://toyshop.example")
	in := w.input(auth.PurposeEnroll, sara)
	opts, state := w.start(in)
	b, _ := a.Create(opts)
	_, err = w.m.Verify(context.Background(), in, state, Response(b))
	wantRefused(t, "the domain, not configured", err, "origin")
}

// §5.13.8: only the transports WebAuthn names are kept, at most eight; the
// state holds no credential list and stays small.
func TestTransportsAndState(t *testing.T) {
	w := newWorld(t)
	a := softauth.New(origin)
	a.Transports = []string{"usb", "warp", "nfc", "usb", "ble", "smart-card", "hybrid", "internal", "carrier-pigeon"}
	w.enroll(a)
	if r := record(t, w.creds[string(a.ID)].c); strings.Join(r.Transports, ",") != "usb,nfc,ble,smart-card,hybrid,internal" {
		t.Errorf("transports %v", r.Transports)
	}
	for i := range 19 {
		b := softauth.New(origin)
		b.ID = bytes.Repeat([]byte{byte(i)}, 1023)
		w.enroll(b)
	}
	_, state := w.start(w.input(auth.PurposeStepUp, sara))
	if len(state) > 128 {
		t.Errorf("state of %d bytes with 20 passkeys", len(state))
	}
}

// §5.13.13: no refusal or failure carries the library's text, the
// challenge or the credential ID.
func TestNoLibraryText(t *testing.T) {
	w := newWorld(t)
	a := softauth.New(origin)
	w.enroll(a)
	a.Origin = "https://evil.example"
	_, err := w.signIn(a, nil)
	if err == nil || strings.Contains(err.Error(), "evil") || strings.Contains(err.Error(), "Origin") {
		t.Errorf("error text: %v", err)
	}
	p := Response([]byte("secret-response"))
	if s := p.(interface{ String() string }).String(); strings.Contains(s, "secret") {
		t.Errorf("proof prints %q", s)
	}
}

func cose(t *testing.T, m map[int]any) []byte {
	t.Helper()
	b, err := webauthncbor.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Review 0022, finding 1: a key that can't verify is refused at
// registration, though attestation none never parses it.
func TestRegistrationKeys(t *testing.T) {
	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	z := make([]byte, 32)
	for name, tc := range map[string]struct {
		key    []byte
		reason string
	}{
		"no coordinates":   {cose(t, map[int]any{1: 2, 3: -7}), "malformed"},
		"off the curve":    {cose(t, map[int]any{1: 2, 3: -7, -1: 1, -2: z, -3: z}), "malformed"},
		"no algorithm":     {cose(t, map[int]any{1: 2, -1: 1, -2: z, -3: z}), "malformed"},
		"unknown type":     {cose(t, map[int]any{1: 99, 3: -7}), "malformed"},
		"RSA as ES256":     {cose(t, map[int]any{1: 3, 3: -7, -1: rsa2048.N.Bytes(), -2: []byte{1, 0, 1}}), "malformed"},
		"RSA of 1024":      {cose(t, map[int]any{1: 3, 3: -257, -1: rsa1024.N.Bytes(), -2: []byte{1, 0, 1}}), "malformed"},
		"RSA exponent 1":   {cose(t, map[int]any{1: 3, 3: -257, -1: rsa2048.N.Bytes(), -2: []byte{1}}), "malformed"},
		"RSA even e":       {cose(t, map[int]any{1: 3, 3: -257, -1: rsa2048.N.Bytes(), -2: []byte{4}}), "malformed"},
		"RSA huge e":       {cose(t, map[int]any{1: 3, 3: -257, -1: rsa2048.N.Bytes(), -2: []byte{0x80, 0, 0, 1}}), "malformed"},
		"RSA of 4097":      {cose(t, map[int]any{1: 3, 3: -257, -1: append([]byte{1}, make([]byte, 512)...), -2: []byte{1, 0, 1}}), "malformed"},
		"short Ed25519":    {cose(t, map[int]any{1: 1, 3: -8, -1: 6, -2: []byte{1}}), "malformed"},
		"Ed25519 as RS256": {cose(t, map[int]any{1: 1, 3: -257, -1: 6, -2: make([]byte, 32)}), "malformed"},
	} {
		w := newWorld(t)
		a := softauth.New(origin)
		a.COSE = tc.key
		in := w.input(auth.PurposeEnroll, sara)
		opts, state := w.start(in)
		b, err := a.Create(opts)
		if err != nil {
			t.Fatal(err)
		}
		_, err = w.m.Verify(context.Background(), in, state, Response(b))
		wantRefused(t, name, err, tc.reason)
	}
	// A self-attestation that verifies is accepted, and decides nothing.
	sw := newWorld(t)
	sa := softauth.New(origin)
	sa.Format = "self"
	sw.enroll(sa)
	if r := record(t, sw.creds[string(sa.ID)].c); r.AttestationFormat != "packed" {
		t.Errorf("format %q", r.AttestationFormat)
	}
	// A good RSA key of 2048 bits is accepted.
	w := newWorld(t)
	a := softauth.New(origin)
	a.Alg = softauth.RS256
	w.enroll(a)
}

// Review 0022, findings 2 and 4: more refusals of a registration.
func TestRegistrationRefusalsMore(t *testing.T) {
	for name, tc := range map[string]struct {
		knob   func(a *softauth.Authenticator)
		late   bool
		reason string
	}{
		"no UP":            {func(a *softauth.Authenticator) { a.NoUP = true }, false, "flags"},
		"top origin alone": {func(a *softauth.Authenticator) { a.TopOrigin = origin }, false, "cross_origin"},
		"another attested": {func(a *softauth.Authenticator) { a.AttestedID = []byte("other") }, false, "malformed"},
		"expired":          {func(a *softauth.Authenticator) {}, true, "expired"},
	} {
		w := newWorld(t)
		a := softauth.New(origin)
		tc.knob(a)
		in := w.input(auth.PurposeEnroll, sara)
		opts, state := w.start(in)
		b, _ := a.Create(opts)
		if tc.late {
			in.Now = in.Now.Add(lifetime)
		}
		_, err := w.m.Verify(context.Background(), in, state, Response(b))
		wantRefused(t, name, err, tc.reason)
	}
}

// Review 0022, findings 2 to 4: more of an assertion.
func TestAssertionMore(t *testing.T) {
	type tc struct {
		reg, knob func(a *softauth.Authenticator)
		user      *auth.User
		reason    string // "" for accepted
	}
	none := func(*softauth.Authenticator) {}
	for name, c := range map[string]tc{
		"AT on a get":      {none, func(a *softauth.Authenticator) { a.AT = true }, nil, "malformed"},
		"a bad signature":  {none, func(a *softauth.Authenticator) { a.BadSig = true }, nil, "signature"},
		"capital origin":   {none, func(a *softauth.Authenticator) { a.Origin = "https://TOYSHOP.example" }, nil, "origin"},
		"default port":     {none, func(a *softauth.Authenticator) { a.Origin = origin + ":443" }, nil, "origin"},
		"BE lost":          {func(a *softauth.Authenticator) { a.BE = true }, func(a *softauth.Authenticator) { a.BE = false }, nil, "backup_flags"},
		"no handle, named": {none, func(a *softauth.Authenticator) { a.NoHandle = true }, sara, ""},
		"BS cleared":       {func(a *softauth.Authenticator) { a.BE, a.BS = true, true }, func(a *softauth.Authenticator) { a.BS = false }, nil, ""},
	} {
		w := newWorld(t)
		a := softauth.New(origin)
		c.reg(a)
		w.enroll(a)
		c.knob(a)
		_, err := w.signIn(a, c.user)
		if c.reason == "" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		wantRefused(t, name, err, c.reason)
	}
	// BS stored as last seen, cleared too.
	w := newWorld(t)
	a := softauth.New(origin)
	a.BE, a.BS = true, true
	w.enroll(a)
	a.BS = false
	if _, err := w.signIn(a, nil); err != nil {
		t.Fatal(err)
	}
	if record(t, w.creds[string(a.ID)].c).BackupState {
		t.Error("BS not cleared")
	}
}

// Review 0022, finding 3: options for a known user with no passkeys still
// refuse anyone else's.
func TestKnownUserNoPasskeys(t *testing.T) {
	w := newWorld(t)
	omar := &auth.User{ID: "u2", Name: "omar"}
	a := softauth.New(origin)
	in := w.input(auth.PurposeEnroll, omar)
	opts, state := w.start(in)
	b, _ := a.Create(opts)
	res, err := w.m.Verify(context.Background(), in, state, Response(b))
	if err != nil {
		t.Fatal(err)
	}
	w.creds[string(a.ID)] = held{"u2", *res.Credential}
	_, err = w.signIn(a, sara)
	wantRefused(t, "omar's passkey for sara", err, "unknown_credential")
}

// Review 0022, finding 4: a user handle of 1 to 64 bytes; a record of
// another version is the method's own failure in Start too.
func TestStartChecks(t *testing.T) {
	w := newWorld(t)
	for _, id := range []auth.UserID{"", auth.UserID(strings.Repeat("x", 65))} {
		if _, _, err := w.m.Start(context.Background(), w.input(auth.PurposeEnroll, &auth.User{ID: id, Name: "x"})); err == nil {
			t.Errorf("a handle of %d bytes: no error", len(id))
		}
	}
	data, _ := proto.Marshal(&passkeypb.Credential{Version: recordVersion + 1})
	w.creds["k"] = held{sara.ID, auth.Credential{Key: []byte("k"), Data: data}}
	if _, _, err := w.m.Start(context.Background(), w.input(auth.PurposeStepUp, sara)); err == nil {
		t.Error("a record of another version: no error")
	}
}

// Review 0022, finding 5.
func TestNewStricter(t *testing.T) {
	for name, c := range map[string]config{
		"hex last label":    {"Toy", "example.0x1", nil},
		"long digits label": {"Toy", "example.123456789012345678901", nil},
		"octal last label":  {"Toy", "example.017", nil},
		"long label":        {"Toy", strings.Repeat("a", 64) + ".example", nil},
		"dash last":         {"Toy", "toy-.example", nil},
		"loose apk hash":    {"Toy", "toyshop.example", []string{"android:apk-key-hash:" + strings.Repeat("A", 42) + "B"}},
	} {
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
