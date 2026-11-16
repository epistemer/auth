package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/text/unicode/norm"

	"github.com/epistemer/auth/internal/secrets"
	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// Codes sent by email or SMS (interface §5.3).

// Challenge is what Challenge prepared.
type Challenge struct {
	Method  string
	SentTo  string     // a masked address; empty before the first proof
	Resend  time.Time  // when another may be asked for
	TOTP    *TOTPSetup // when enrolling an authenticator app
	Options any        // a module's own answer: passkey options, a redirect URL
}

// TOTPSetup is what an authenticator app needs to enroll.
type TOTPSetup struct {
	Secret string // base32
	URI    string // otpauth://
}

// The kinds of send counter (§5.3.5), beside the throttle's in the same
// bucket. A counter's Failures is the number sent, its Last the start of
// its hour.
const (
	sentUser = "sent_user"
	sentAddr = "sent_addr"
)

// codeChannel is the channel a code method sends through.
func codeChannel(method string) (Channel, bool) {
	switch method {
	case MethodEmailCode, MethodEmailLink:
		return ChannelEmail, true
	case MethodSMSCode:
		return ChannelSMS, true
	}
	return 0, false
}

// Challenge prepares a proof. For a code it sends one, and it answers the
// same whether or not a message went: for an unknown login, a user with no
// address, a failed send, inside code.resend and past code.hourly (§5.1.5).
// What happened is an event. Before the first proof SentTo is empty.
func (a *Auth) Challenge(ctx context.Context, token, method string) (Challenge, error) {
	hash := secrets.Hash(token)
	rec, err := a.loadFlow(hash)
	if err != nil {
		return Challenge{}, err
	}
	v, err := a.view(ctx, rec, nil)
	if err != nil {
		return Challenge{}, err
	}
	if !slices.Contains(v.offers, method) || method == MethodEmailLink && Purpose(rec.Purpose) != PurposeRecover {
		return Challenge{}, ErrMethodUnavailable
	}
	if method == MethodTOTP && Purpose(rec.Purpose) == PurposeEnroll && rec.EnrollMethod == MethodTOTP {
		return a.challengeTOTP(ctx, hash, rec)
	}
	ch, ok := codeChannel(method)
	if !ok {
		// A password, or an authenticator app's code, needs nothing
		// prepared.
		return Challenge{Method: method}, nil
	}
	return a.challengeCode(ctx, token, hash, rec, method, ch)
}

// challengeCode sends a code, or for MethodEmailLink a link, which carries
// the flow's token sealed so Follow can return the same flow (§5.3.6).
func (a *Auth) challengeCode(ctx context.Context, token string, hash []byte, rec *storepb.Flow, method string, ch Channel) (Challenge, error) {
	isLink := method == MethodEmailLink
	link, linkHash := secrets.NewToken()
	ev := Event{Kind: "code.not_sent", User: UserID(rec.UserId), Session: SessionID(rec.SessionId), Method: method}
	before := !a.firstProven(rec)
	var addr string
	switch {
	case rec.UserId == "":
		ev.Reason = "no_user"
	default:
		got, err := a.dir.Address(ctx, UserID(rec.UserId), ch)
		switch {
		case err != nil:
			ev.Reason = "directory_error"
		case got == "":
			ev.Reason = "no_address"
		default:
			addr = got
		}
	}
	code, err := newCode(a.cfg.AuthCodeLength())
	if err != nil {
		return Challenge{}, err
	}
	var send bool
	var sent, expires int64
	err = a.db.Update(func(tx *bolt.Tx) error {
		cur := new(storepb.Flow)
		if err := store.Get(tx, store.Flows, hash, cur); err != nil {
			return err
		}
		now := a.now().UnixNano()
		if now >= cur.Expires {
			return store.ErrNotFound
		}
		send = false
		// A Recover's first proofs stop being offered once one is made; a
		// Challenge that read the offers before then sends nothing now.
		if Purpose(cur.Purpose) == PurposeRecover && slices.Contains(recoverFirst, method) && a.firstProven(cur) {
			return errOffered
		}
		i := slices.IndexFunc(cur.Codes, func(c *storepb.CodeState) bool { return c.Method == method })
		if i >= 0 && now < cur.Codes[i].Sent+int64(a.cfg.AuthCodeResend()) {
			// Inside code.resend: nothing is sent, and the code stands.
			sent = cur.Codes[i].Sent
			ev.Reason = "resend"
			return nil
		}
		sent = now
		if addr != "" {
			ok, err := a.allowSend(tx, UserID(cur.UserId), addr, now)
			if err != nil {
				return err
			}
			if !ok {
				ev.Reason = "hourly"
			}
			send = ok
		}
		// Every Challenge past code.resend replaces the code, sent or not
		// (§5.3.3), so the flow behaves the same whatever happened: a code
		// to guess, a lifetime, a wait. A code no one is sent has a random
		// MAC, which no code matches: it can't be guessed.
		mac := a.keys.MAC(secrets.Codes, hash, []byte{byte(cur.Purpose)}, []byte(method), []byte(code))
		if !send {
			mac = make([]byte, len(mac))
			rand.Read(mac)
		}
		expires = now + int64(a.cfg.AuthCodeLifetime())
		if isLink {
			// A link replaces the last one: the flow names only its own.
			mac, expires = nil, a.linkExpiry(now)
			if len(cur.LinkHash) > 0 {
				if err := store.Delete(tx, store.Links, cur.LinkHash); err != nil {
					return err
				}
			}
			cur.LinkHash = linkHash
			if send {
				sealed, err := secrets.SealWith(secrets.KeyFromToken([]byte(link), "flow"), []byte(token), linkHash)
				if err != nil {
					return err
				}
				l := &storepb.Link{
					Purpose: cur.Purpose, UserId: cur.UserId, FlowHash: hash, Created: now, Expires: expires,
					FlowToken: sealed, Channel: channelKey(addr),
				}
				if err := store.Put(tx, store.Links, linkHash, l); err != nil {
					return err
				}
			}
		}
		cs := &storepb.CodeState{Method: method, Mac: mac, Channel: channelKey(addr), Sent: now, Expires: expires}
		if i >= 0 {
			cur.Codes[i] = cs // a new code cancels the old (§5.3.3)
		} else {
			cur.Codes = append(cur.Codes, cs)
		}
		return store.Put(tx, store.Flows, hash, cur)
	})
	if errors.Is(err, store.ErrNotFound) {
		return Challenge{}, ErrFlowExpired
	}
	if errors.Is(err, errOffered) {
		return Challenge{}, ErrMethodUnavailable
	}
	if err != nil {
		return Challenge{}, err
	}
	if send {
		m := Message{Kind: a.codeKind(rec), Channel: ch, To: addr, User: UserID(rec.UserId), Code: code, Expires: time.Unix(0, expires)}
		if isLink {
			m.Kind, m.Code, m.Token = MsgRecoveryLink, "", link
		}
		err := a.sender.Send(ctx, m)
		if err != nil {
			ev.Reason = "send_failed"
			// Nothing went: the send doesn't count toward code.hourly.
			if err := a.db.Update(func(tx *bolt.Tx) error { return a.refundSend(tx, UserID(rec.UserId), addr, sent) }); err != nil {
				return Challenge{}, err
			}
		} else {
			ev.Kind, ev.Reason = "code.sent", ""
		}
	}
	a.record(ctx, ev)
	out := Challenge{Method: method, Resend: time.Unix(0, sent).Add(a.cfg.AuthCodeResend())}
	if !before && addr != "" {
		out.SentTo = mask(addr, ch)
	}
	return out, nil
}

// errOffered is a Challenge for a method the flow stopped offering.
var errOffered = errors.New("auth: the method is no longer offered")

// codeKind is the message a flow's code goes out as.
func (a *Auth) codeKind(rec *storepb.Flow) MessageKind {
	if Purpose(rec.Purpose) == PurposeRecover {
		return MsgRecoveryCode
	}
	return MsgSignInCode
}

// firstProven reports whether a flow holds a proof of a first method; for
// a flow that isn't a SignIn, whether it holds any proof or is bound to a
// session, which proved one.
func (a *Auth) firstProven(rec *storepb.Flow) bool {
	if Purpose(rec.Purpose) != PurposeSignIn {
		return len(rec.Proofs) > 0 || rec.SessionId != ""
	}
	return slices.ContainsFunc(rec.Proofs, func(p *storepb.Factor) bool { return slices.Contains(a.first, p.Method) })
}

// sendKeys are the send counters of a user and an address.
func sendKeys(user UserID, addr string) [][]byte {
	return [][]byte{
		store.Key([]byte(sentUser), []byte(hex.EncodeToString(digest("user", []byte(user))))),
		store.Key([]byte(sentAddr), []byte(hex.EncodeToString(channelKey(addr)))),
	}
}

// allowSend counts a send against the user's and the address's limits, in
// tx, and reports whether it may go: at most code.hourly in any hour, over
// a sliding window of the sends' times (§5.3.5). A counter's Last is its
// latest send, which Sweep keeps it an hour past.
func (a *Auth) allowSend(tx *bolt.Tx, user UserID, addr string, now int64) (bool, error) {
	limit := a.cfg.AuthCodeHourly()
	keys := sendKeys(user, addr)
	recs := make([]*storepb.Counter, len(keys))
	for i, k := range keys {
		c := new(storepb.Counter)
		if err := store.Get(tx, store.Throttle, k, c); err != nil && !errors.Is(err, store.ErrNotFound) {
			return false, err
		}
		c.Sent = slices.DeleteFunc(c.Sent, func(t int64) bool { return now-t >= int64(time.Hour) })
		if len(c.Sent) >= limit {
			return false, nil
		}
		recs[i] = c
	}
	for i, k := range keys {
		recs[i].Sent = append(recs[i].Sent, now)
		recs[i].Failures = uint32(len(recs[i].Sent))
		recs[i].Last = now
		recs[i].Seq++
		if err := store.Put(tx, store.Throttle, k, recs[i]); err != nil {
			return false, err
		}
	}
	return true, nil
}

// refundSend takes back a send that failed.
func (a *Auth) refundSend(tx *bolt.Tx, user UserID, addr string, at int64) error {
	for _, k := range sendKeys(user, addr) {
		c := new(storepb.Counter)
		if err := store.Get(tx, store.Throttle, k, c); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return err
		}
		if i := slices.Index(c.Sent, at); i >= 0 {
			c.Sent = slices.Delete(c.Sent, i, i+1)
			c.Failures = uint32(len(c.Sent))
			c.Seq++
			if err := store.Put(tx, store.Throttle, k, c); err != nil {
				return err
			}
		}
	}
	return nil
}

// channelKey is how an address appears in a record: the SHA-256 of its
// normalized form, so two proofs through one address can be told apart
// from two through two (§5.7.2) without storing the address. None for none.
func channelKey(addr string) []byte {
	n := normalizeAddr(addr)
	if n == "" {
		return nil
	}
	s := sha256.Sum256([]byte(n))
	return s[:]
}

// normalizeAddr folds an address's case and width, and a phone number's
// punctuation.
func normalizeAddr(addr string) string {
	a := strings.ToLower(strings.TrimSpace(norm.NFKC.String(addr)))
	if strings.Contains(a, "@") {
		return a
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) || r == '+' {
			return r
		}
		return -1
	}, a)
}

// mask shows enough of an address for its owner to know it: an email's
// first letter and domain, a phone's last two digits.
func mask(addr string, ch Channel) string {
	if ch == ChannelEmail {
		local, domain, ok := strings.Cut(strings.TrimSpace(norm.NFKC.String(addr)), "@")
		if ok && local != "" && domain != "" {
			r := []rune(local)
			return string(r[0]) + "•••@" + domain
		}
		return "•••"
	}
	digits := []rune(normalizeAddr(addr))
	if len(digits) <= 2 {
		return "•••"
	}
	return "•••" + string(digits[len(digits)-2:])
}

// newCode draws n decimal digits uniformly (§5.3.1).
func newCode(n int) (string, error) {
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
	v, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", n, v), nil
}

// proveCode checks a code. The try is counted before the code is compared,
// in the same transaction, and the code is burnt by its last try or its
// first success (§5.3.4).
func (a *Auth) proveCode(ctx context.Context, token string, hash []byte, rec *storepb.Flow, v view, method, code string) (Flow, error) {
	before := a.flowOut(token, rec, v)
	sub, err := a.subjectFor(ctx, rec)
	if err != nil {
		return before, err
	}
	at, err := a.count(sub)
	if err != nil {
		if errors.Is(err, ErrTooManyAttempts) {
			a.record(ctx, Event{Kind: "proof.refused", User: UserID(rec.UserId), Session: SessionID(rec.SessionId), Method: method, Reason: "throttled"})
		}
		return before, err
	}
	var channel []byte
	reason := ""
	err = a.db.Update(func(tx *bolt.Tx) error {
		cur := new(storepb.Flow)
		if err := store.Get(tx, store.Flows, hash, cur); err != nil {
			return err
		}
		now := a.now().UnixNano()
		if now >= cur.Expires {
			return store.ErrNotFound
		}
		i := slices.IndexFunc(cur.Codes, func(c *storepb.CodeState) bool { return c.Method == method })
		switch {
		case i < 0:
			reason = "no_code"
			return nil
		case cur.Codes[i].Burnt:
			reason = "used"
			return nil
		case now >= cur.Codes[i].Expires:
			reason = "expired"
			return nil
		}
		cs := cur.Codes[i]
		cs.Tries++
		// The MAC is checked whatever the login, so every try costs the
		// same; an unknown login's code was never sent, and nothing matches.
		match := a.keys.Verify(secrets.Codes, cs.Mac, hash, []byte{byte(cur.Purpose)}, []byte(method), []byte(code))
		switch {
		case cs.Tries > uint32(a.cfg.AuthCodeTries()):
			// code.tries was lowered while the code lived.
			cs.Burnt, reason = true, "tries"
		case match && cur.UserId != "":
			cs.Burnt, channel = true, cs.Channel
		default:
			reason = "bad_code"
			if cs.Tries == uint32(a.cfg.AuthCodeTries()) {
				cs.Burnt = true
			}
		}
		return store.Put(tx, store.Flows, hash, cur)
	})
	if errors.Is(err, store.ErrNotFound) {
		return before, ErrFlowExpired
	}
	if err != nil {
		return before, err
	}
	if reason != "" {
		a.record(ctx, Event{Kind: "proof.refused", User: UserID(rec.UserId), Session: SessionID(rec.SessionId), Method: method, Reason: reason})
		return before, ErrBadCode
	}
	u, err := a.user(ctx, UserID(rec.UserId))
	if err != nil {
		return before, err
	}
	if u.Disabled {
		a.record(ctx, Event{Kind: "proof.refused", User: u.ID, Session: SessionID(rec.SessionId), Method: method, Reason: "disabled"})
		return before, ErrUserDisabled
	}
	if err := a.succeed(at); err != nil {
		return before, err
	}
	rec, err = a.addProof(hash, &storepb.Factor{Method: method, At: a.now().UnixNano(), Channel: channel})
	if err != nil {
		return before, err
	}
	a.record(ctx, Event{Kind: "proof.accepted", User: u.ID, Session: SessionID(rec.SessionId), Method: method})
	v, err = a.view(ctx, rec, nil)
	if err != nil {
		return before, err
	}
	out := a.flowOut(token, rec, v)
	if v.cannot {
		return out, ErrCannotVerify
	}
	return out, nil
}

// addresses returns the code methods a user can be sent: those whose
// channel the directory has an address for.
func (a *Auth) addresses(ctx context.Context, u User) ([]string, error) {
	var out []string
	for _, m := range []string{MethodEmailCode, MethodSMSCode} {
		ch, _ := codeChannel(m)
		addr, err := a.dir.Address(ctx, u.ID, ch)
		if err != nil {
			return nil, fmt.Errorf("auth: an address: %w", err)
		}
		if addr != "" {
			out = append(out, m)
		}
	}
	return out, nil
}
