package auth

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// Methods from modules (interface §4.9, §5.5, amendment A21).

const (
	maxModuleState = 4 << 10 // §4.9: a method's state is at most 4 KiB
	maxChallenges  = 10      // §5.5.9: per flow and module method
	maxRefusals    = 5
)

// methodLimit is how many credentials of a method one user may hold, where
// the method's section sets a limit (§5.13.2).
var methodLimit = map[string]int{MethodPasskey: 20}

// addrOnly are the methods whose attempts count toward the address's
// counter alone, or a registered device's pair counter (§5.13.11): their
// proofs are signatures over a challenge, with nothing to guess.
var addrOnly = map[string]bool{MethodPasskey: true}

// stateKey is where a flow keeps a module method's state, apart from the
// core's own entries in the same map.
func stateKey(method string) string { return "m:" + method }

// moduleFirst are the first methods that come from modules.
func (a *Auth) moduleFirst() []string {
	return slices.DeleteFunc(slices.Clone(a.first), func(m string) bool { return a.methods[m] == nil })
}

// available reports whether a method can be proved here: a built-in one,
// or a module's that was given to WithMethods.
func (a *Auth) available(m string) bool { return coreMethods[m] || a.methods[m] != nil }

// capped reports whether a module method has had its Challenges or its
// refused proofs in rec (§5.5.9): it takes no more Challenges.
func capped(rec *storepb.Flow, m string) bool {
	return rec.Challenges[m] >= maxChallenges || rec.Refusals[m] >= maxRefusals
}

// spent reports whether a module method is no longer offered in rec: past
// its refusals, or past its Challenges with no state left to prove, so
// the tenth Challenge can still be answered (review 0021).
func spent(rec *storepb.Flow, m string) bool {
	if rec.Refusals[m] >= maxRefusals {
		return true
	}
	_, pending := rec.MethodState[stateKey(m)]
	return rec.Challenges[m] >= maxChallenges && !pending
}

// SignInWithout starts a sign-in that names no login, for a method that
// finds the user from its proof, such as a passkey in autofill. Its offers
// are WithFirst's module methods; with none it is ErrMethodUnavailable. The
// Directory isn't asked. A device token the request presents is read now:
// it serves throttling, and stands for nothing if the proof names another
// user (§4.3). Its attempts have no user's counter before the proof, so a
// method served through it must have nothing to guess, as a passkey (A22).
func (a *Auth) SignInWithout(ctx context.Context, c Carrier) (Flow, error) {
	switch c.c {
	case storepb.Carrier_CARRIER_COOKIE, storepb.Carrier_CARRIER_BEARER:
	default:
		return Flow{}, errors.New("auth: SignInWithout needs auth.Cookie() or auth.Bearer()")
	}
	if len(a.moduleFirst()) == 0 {
		return Flow{}, ErrMethodUnavailable
	}
	rec := &storepb.Flow{Purpose: int32(PurposeSignIn), Carrier: c.c, Without: true}
	if c.c == storepb.Carrier_CARRIER_COOKIE {
		if token := deviceFromCookie(ctx); token != "" {
			if err := a.db.View(func(tx *bolt.Tx) error {
				d, err := a.anyDevice(tx, token)
				if d != nil {
					rec.DeviceId, rec.DeviceToken = d.Id, d.TokenHash
				}
				return err
			}); err != nil {
				return Flow{}, err
			}
		}
	}
	return a.start(ctx, rec)
}

// handed is a credential a method was handed, as it was handed.
type handed struct {
	owner UserID
	data  []byte
}

// tracker remembers the credentials Find, Lookup and Credentials handed to
// one Verify, for rule 8 of §5.5.
type tracker struct {
	mu sync.Mutex
	m  map[string]handed
}

func (t *tracker) hand(owner UserID, cs ...Credential) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[string]handed{}
	}
	for _, c := range cs {
		t.m[string(c.Key)] = handed{owner, bytes.Clone(c.Data)}
	}
}

func (t *tracker) get(key []byte) (handed, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	h, ok := t.m[string(key)]
	return h, ok
}

// credentialIndex is a credential's key in credential_keys.
func credentialIndex(method string, key []byte) []byte {
	return append(store.Prefix([]byte(method)), store.CredKey(key)...)
}

func toCredential(c *storepb.Credential) Credential {
	return Credential{Key: bytes.Clone(c.Key), Data: bytes.Clone(c.Data), Label: c.Label}
}

// credentialsTx are a user's credentials of one method.
func credentialsTx(tx *bolt.Tx, user UserID, method string) ([]Credential, error) {
	var out []Credential
	err := store.Scan(tx, store.Credentials, store.Prefix([]byte(user), []byte(method)), func(_, v []byte) error {
		var c storepb.Credential
		if err := proto.Unmarshal(v, &c); err != nil {
			return err
		}
		out = append(out, toCredential(&c))
		return nil
	})
	return out, err
}

// findCredentialTx finds a credential of a method by its key, through
// credential_keys: its owner and record, or "" and nil.
func findCredentialTx(tx *bolt.Tx, method string, key []byte) (UserID, *storepb.Credential, error) {
	owner := store.B(tx, store.CredentialKeys).Get(credentialIndex(method, key))
	if owner == nil {
		return "", nil, nil
	}
	user := UserID(bytes.Clone(owner))
	c := new(storepb.Credential)
	if err := store.Get(tx, store.Credentials, credentialKey(user, method, key), c); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", nil, nil
		}
		return "", nil, err
	}
	return user, c, nil
}

// methodInput is what a method is told of a flow (§4.9). In a flow started
// without a session, until its first proof, it has no user and no
// credentials, whatever the login: a method can't answer differently for
// a known login. Find and Lookup read the store when called, and t
// remembers what they handed out.
func (a *Auth) methodInput(ctx context.Context, rec *storepb.Flow, method string, t *tracker) (MethodInput, error) {
	in := MethodInput{Purpose: Purpose(rec.Purpose), Now: a.now()}
	if rec.UserId != "" && (rec.SessionId != "" || len(rec.Proofs) > 0) {
		u, err := a.user(ctx, UserID(rec.UserId))
		if err != nil {
			return MethodInput{}, err
		}
		var cs []Credential
		if err := a.db.View(func(tx *bolt.Tx) (err error) {
			cs, err = credentialsTx(tx, u.ID, method)
			return err
		}); err != nil {
			return MethodInput{}, err
		}
		in.User, in.Credentials = &u, cs
		t.hand(u.ID, cs...)
	}
	in.Find = func(key []byte) (UserID, *Credential, error) {
		var owner UserID
		var c *storepb.Credential
		if err := a.db.View(func(tx *bolt.Tx) (err error) {
			owner, c, err = findCredentialTx(tx, method, key)
			return err
		}); err != nil || c == nil {
			return "", nil, err
		}
		out := toCredential(c)
		t.hand(owner, out)
		return owner, &out, nil
	}
	in.Lookup = func(id UserID) (User, []Credential, error) {
		if err := validID(id); err != nil {
			return User{}, nil, err
		}
		u, err := a.dir.Get(ctx, id)
		if errors.Is(err, ErrNoUser) {
			return User{}, nil, nil
		}
		if err != nil {
			return User{}, nil, fmt.Errorf("auth: getting user: %w", err)
		}
		if u.ID != id {
			return User{}, nil, fmt.Errorf("auth: the directory returned another user for an ID")
		}
		var cs []Credential
		if err := a.db.View(func(tx *bolt.Tx) (err error) {
			cs, err = credentialsTx(tx, id, method)
			return err
		}); err != nil {
			return User{}, nil, err
		}
		t.hand(id, cs...)
		return u, cs, nil
	}
	return in, nil
}

// challengeModule calls a module's Start and keeps its state in the flow,
// replacing any earlier state of the method (§4.9, §5.5.9).
func (a *Auth) challengeModule(ctx context.Context, hash []byte, rec *storepb.Flow, m Method) (Challenge, error) {
	name := m.Name()
	// Past its Challenges the method isn't asked at all (review 0023).
	if capped(rec, name) {
		return Challenge{}, ErrMethodUnavailable
	}
	in, err := a.methodInput(ctx, rec, name, nil)
	if err != nil {
		return Challenge{}, err
	}
	out, state, err := m.Start(ctx, in)
	if err != nil {
		return Challenge{}, err
	}
	if len(state) > maxModuleState {
		return Challenge{}, fmt.Errorf("auth: method %q kept %d bytes of state, over 4 KiB", name, len(state))
	}
	err = a.db.Update(func(tx *bolt.Tx) error {
		cur := new(storepb.Flow)
		if err := store.Get(tx, store.Flows, hash, cur); err != nil {
			return err
		}
		if a.now().UnixNano() >= cur.Expires {
			return store.ErrNotFound
		}
		// A proof made while Start ran changes what the method should have
		// been told, the user and their credentials: its options are stale
		// (review 0023).
		if capped(cur, name) || len(cur.Proofs) != len(rec.Proofs) || cur.UserId != rec.UserId {
			return errOffered
		}
		if cur.MethodState == nil {
			cur.MethodState = map[string][]byte{}
		}
		if cur.Challenges == nil {
			cur.Challenges = map[string]uint32{}
		}
		cur.MethodState[stateKey(name)] = append([]byte{}, state...)
		cur.Challenges[name]++
		return store.Put(tx, store.Flows, hash, cur)
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Challenge{}, ErrFlowExpired
	case errors.Is(err, errOffered):
		return Challenge{}, ErrMethodUnavailable
	case err != nil:
		return Challenge{}, err
	}
	return Challenge{Method: name, Options: out}, nil
}

// moduleSubject is whom a module's attempt is counted against (§5.5.9):
// the user's and the pair's counters of the method's own kind and the
// address's, or for a passkey the address's alone, or a registered
// device's pair counter (§5.13.11). In a SignInWithout flow, before a
// proof names the user, the device's owner stands for the user.
func (a *Auth) moduleSubject(ctx context.Context, rec *storepb.Flow, method string) (subject, error) {
	r := rec
	if rec.UserId == "" && rec.DeviceId != "" {
		owner, err := a.deviceOwner(rec)
		if err != nil {
			return subject{}, err
		}
		if owner != "" {
			r = proto.Clone(rec).(*storepb.Flow)
			r.UserId = string(owner)
		}
	}
	s, err := a.subjectFor(ctx, r)
	if err != nil {
		return subject{}, err
	}
	if r != rec && !s.device {
		// A device the owner's policy doesn't trust stands for no one: the
		// attempt counts toward the address alone (A22, review 0021).
		s.user = nil
	}
	s.module, s.addrOnly = method, addrOnly[method]
	return s, nil
}

// errRace is a module proof whose state was replaced or used meanwhile.
var errRace = errors.New("auth: the method's state was replaced or used")

// proveModule runs rule 6 of §5.5: check, count, Verify, then one write
// transaction that takes the state and records the outcome.
func (a *Auth) proveModule(ctx context.Context, token string, hash []byte, rec *storepb.Flow, v view, m Method, p Proof) (Flow, error) {
	before := a.flowOut(token, rec, v)
	name := m.Name()
	refused := func(user UserID, reason string) {
		a.record(ctx, Event{Kind: "proof.refused", User: user, Session: SessionID(rec.SessionId), Method: name, Reason: reason})
	}
	// (a) Nothing to verify against is no attempt.
	state, ok := rec.MethodState[stateKey(name)]
	if !ok {
		refused(UserID(rec.UserId), "no_challenge")
		return before, ErrBadCredentials
	}
	// (b) Counted before it is checked.
	sub, err := a.moduleSubject(ctx, rec, name)
	if err != nil {
		return before, err
	}
	at, err := a.count(sub)
	if err != nil {
		if errors.Is(err, ErrTooManyAttempts) {
			refused(UserID(rec.UserId), "throttled")
		}
		return before, err
	}
	// (c) Verify, on the state the flow holds.
	t := new(tracker)
	in, err := a.methodInput(ctx, rec, name, t)
	if err != nil {
		_ = a.refund(at)
		return before, err
	}
	res, verr := m.Verify(ctx, in, state, p)
	var reason string
	var own error
	var ref refusal
	switch {
	case verr == nil:
	case errors.As(verr, &ref):
		reason = ref.reason
	default:
		own = verr
	}
	enroll := Purpose(rec.Purpose) == PurposeEnroll
	// Rules 3 and 7: whom the proof names.
	target := UserID(rec.UserId)
	if reason == "" && own == nil {
		switch {
		case in.User == nil && res.User == "":
			// Told no user, it must name one: the flow's login can't stand
			// in, or a known login and an unknown one would answer apart
			// (review 0021).
			reason = "user_mismatch"
		case res.User != "" && rec.NoUser:
			reason = "user_mismatch"
		case res.User != "" && target != "" && res.User != target:
			reason = "user_mismatch"
		case res.User != "":
			target = res.User
		}
		// A proof that names no one, on a flow that knows no one, is
		// refused below: validID refuses an empty target.
	}
	// Rule 8, from what was handed out; the store is checked again below.
	var h handed
	if reason == "" && own == nil {
		switch {
		case enroll && (res.Credential == nil || len(res.Credential.Key) == 0):
			own = fmt.Errorf("auth: method %q enrolled no credential", name)
		case enroll && len(res.Credential.Key) > 1023:
			own = fmt.Errorf("auth: method %q enrolled a credential key over 1023 bytes", name)
		case !enroll && res.Credential != nil:
			var ok bool
			if h, ok = t.get(res.Credential.Key); !ok {
				reason = "changed"
			} else if h.owner != target {
				reason = "user_mismatch"
			}
		}
	}
	var u User
	if reason == "" && own == nil {
		if err := validID(target); err != nil {
			reason = "user_mismatch"
		} else if u, err = a.dir.Get(ctx, target); errors.Is(err, ErrNoUser) {
			reason = "user_mismatch"
		} else if err != nil {
			own = fmt.Errorf("auth: getting user: %w", err)
		} else if u.ID != target {
			own = fmt.Errorf("auth: the directory returned another user for an ID")
		}
	}
	// (d)–(g) in one transaction.
	var disabled, stale bool
	got := new(storepb.Flow)
	err = a.db.Update(func(tx *bolt.Tx) error {
		disabled, stale = false, false
		cur := got
		proto.Reset(cur)
		if err := store.Get(tx, store.Flows, hash, cur); err != nil {
			return err
		}
		now := a.now().UnixNano()
		if now >= cur.Expires {
			return store.ErrNotFound
		}
		st, ok := cur.MethodState[stateKey(name)]
		if !ok || !bytes.Equal(st, state) {
			return errRace
		}
		delete(cur.MethodState, stateKey(name))
		put := func() error { return store.Put(tx, store.Flows, hash, cur) }
		if own != nil {
			return put()
		}
		if reason == "" && !enroll && res.Credential != nil {
			owner, c, err := findCredentialTx(tx, name, res.Credential.Key)
			if err != nil {
				return err
			}
			if c == nil || owner != target || !bytes.Equal(c.Data, h.data) {
				reason = "changed"
			}
		}
		if reason == "" && enroll && store.B(tx, store.CredentialKeys).Get(credentialIndex(name, res.Credential.Key)) != nil {
			reason = "duplicate"
		}
		if reason != "" {
			if cur.Refusals == nil {
				cur.Refusals = map[string]uint32{}
			}
			cur.Refusals[name]++
			return put()
		}
		// (f) The flow's own checks.
		if u.Disabled {
			disabled = true
			return put()
		}
		if cur.UserId == "" {
			// A device presented at the start then stands for nothing if
			// the proof names someone else: flowDevice and subjectFor find a
			// device only of the flow's user.
			cur.UserId = string(target)
		}
		var err error
		if stale, err = staleTx(tx, cur); err != nil || stale {
			if err != nil {
				return err
			}
			return put()
		}
		// (g) The proof, and the credential's update or its pending copy.
		f := &storepb.Factor{Method: name, At: now, Verified: res.Verified}
		if i := slices.IndexFunc(cur.Proofs, func(p *storepb.Factor) bool { return p.Method == name }); i >= 0 {
			cur.Proofs[i].At = max(cur.Proofs[i].At, f.At)
			cur.Proofs[i].Verified = cur.Proofs[i].Verified || f.Verified
		} else {
			cur.Proofs = append(cur.Proofs, f)
		}
		switch {
		case enroll:
			b, err := proto.Marshal(&storepb.Credential{
				Method: name, Key: res.Credential.Key, Data: res.Credential.Data, Label: res.Credential.Label,
			})
			if err != nil {
				return err
			}
			cur.Pending = b
		case res.Credential != nil:
			key := credentialKey(target, name, res.Credential.Key)
			var c storepb.Credential
			if err := store.Get(tx, store.Credentials, key, &c); err != nil {
				return err
			}
			c.Data, c.Used = bytes.Clone(res.Credential.Data), now
			if err := store.Put(tx, store.Credentials, key, &c); err != nil {
				return err
			}
		}
		return put()
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		_ = a.refund(at)
		return before, ErrFlowExpired
	case errors.Is(err, errRace):
		// Its Verify's answer is thrown away: nothing was judged, so its
		// count is taken back. Each state is judged once, whatever races.
		_ = a.refund(at)
		refused(UserID(rec.UserId), "no_challenge")
		return before, ErrBadCredentials
	case err != nil:
		_ = a.refund(at)
		return before, err
	case own != nil:
		_ = a.refund(at)
		return before, own
	case reason != "":
		refused(UserID(rec.UserId), reason)
		return before, ErrBadCredentials
	case disabled:
		refused(target, "disabled")
		return before, ErrUserDisabled
	case stale:
		_ = a.refund(at)
		return before, ErrFlowExpired
	}
	// Clear the counters only of the user the proof named. One counted
	// against another user (the owner of a device someone else presented)
	// takes back its count and clears nothing of theirs (review 0021).
	release := a.succeed
	if !bytes.Equal(sub.user, digest("user", []byte(target))) {
		release = a.refund
	}
	if err := release(at); err != nil {
		return before, err
	}
	a.record(ctx, Event{Kind: "proof.accepted", User: target, Session: SessionID(got.SessionId), Method: name})
	v, err = a.view(ctx, got, nil)
	if err != nil {
		return before, err
	}
	out := a.flowOut(token, got, v)
	if v.cannot {
		return out, ErrCannotVerify
	}
	return out, nil
}

// factorLabel is the label a factor is stored with: FactorLabel's, without
// control characters and cut at 64 runes, else the method's own.
func factorLabel(o finishOptions, own string) string {
	if o.label != nil {
		if l := cleanLabel(*o.label); l != "" {
			return l
		}
	}
	return own
}

// cleanLabel drops control characters, cuts a label at 64 runes, and
// gives "" for one that is then blank.
func cleanLabel(l string) string {
	l = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, l)
	if utf8.RuneCountInString(l) > 64 {
		l = string([]rune(l)[:64])
	}
	if strings.TrimSpace(l) == "" {
		return ""
	}
	return l
}

// methodOwnLabel is a module credential's label when FactorLabel gives
// none: the method's, or for a passkey "Passkey".
func methodOwnLabel(method string, c *storepb.Credential) string {
	l := cleanLabel(c.Label)
	switch {
	case l != "":
		return l
	case method == MethodPasskey:
		return "Passkey"
	}
	return method
}

// countMethodTx counts a user's credentials of one method.
func countMethodTx(tx *bolt.Tx, user UserID, method string) (int, error) {
	n := 0
	err := store.Scan(tx, store.Credentials, store.Prefix([]byte(user), []byte(method)), func(_, _ []byte) error {
		n++
		return nil
	})
	return n, err
}

// enrollModuleTx stores the credential an Enroll flow proved, or refuses it
// (rule 10 of §5.5): then it drops the pending credential and its proof
// from the flow, which stays, and returns the refusal's reason, with a nil
// error so the transaction commits that. It returns the recovery codes the
// first factor brings.
func (a *Auth) enrollModuleTx(tx *bolt.Tx, hash []byte, cur *storepb.Flow, o finishOptions) (codes []string, refused string, err error) {
	method, user := cur.EnrollMethod, UserID(cur.UserId)
	var c storepb.Credential
	if len(cur.Pending) == 0 || proto.Unmarshal(cur.Pending, &c) != nil || c.Method != method || len(c.Key) == 0 {
		return nil, "", errChanged
	}
	if a.now().UnixNano() >= cur.Expires {
		return nil, "", store.ErrNotFound
	}
	reason := ""
	if store.B(tx, store.CredentialKeys).Get(credentialIndex(method, c.Key)) != nil {
		reason = "duplicate"
	} else if limit := methodLimit[method]; limit > 0 {
		n, err := countMethodTx(tx, user, method)
		if err != nil {
			return nil, "", err
		}
		if n >= limit {
			reason = "limit"
		}
	}
	if reason != "" {
		cur.Pending = nil
		cur.Proofs = slices.DeleteFunc(cur.Proofs, func(p *storepb.Factor) bool { return p.Method == method })
		return nil, reason, store.Put(tx, store.Flows, hash, cur)
	}
	if _, err := a.spend(tx, hash); err != nil {
		return nil, "", err
	}
	before, err := enrolledTx(tx, user)
	if err != nil {
		return nil, "", err
	}
	now := a.now().UnixNano()
	stored := &storepb.Credential{
		Method: method, Key: c.Key, Data: c.Data, Label: factorLabel(o, methodOwnLabel(method, &c)),
		Added: now,
	}
	if err := store.Put(tx, store.Credentials, credentialKey(user, method, c.Key), stored); err != nil {
		return nil, "", err
	}
	if err := store.B(tx, store.CredentialKeys).Put(credentialIndex(method, c.Key), []byte(user)); err != nil {
		return nil, "", err
	}
	// The first factor brings a set of recovery codes (§5.4.6).
	if isSecond(method) && len(before) == 0 {
		codes, err = a.newRecoverySet(tx, user)
		return codes, "", err
	}
	return nil, "", nil
}
