package auth

import (
	"context"
	"regexp"
	"time"
)

// Method is a way of proving who a user is, from a module (interface §4.9).
// The engine, not the method, applies throttling, events, the policy and
// the rules of §5.1 around these calls.
type Method interface {
	Name() string
	// Start makes what the client needs to produce a proof, and state the
	// flow keeps until Verify.
	Start(ctx context.Context, in MethodInput) (out any, state []byte, err error)
	Verify(ctx context.Context, in MethodInput, state []byte, proof Proof) (MethodResult, error)
}

// MethodInput is what a method knows of the flow.
type MethodInput struct {
	Purpose     Purpose
	User        *User        // nil when the flow doesn't know the user yet
	Credentials []Credential // the user's credentials for this method
	Find        func(key []byte) (UserID, *Credential, error)
	Lookup      func(id UserID) (User, []Credential, error)
	Now         time.Time // the engine's clock (WithClock)
}

// Credential is a method's record for one user.
type Credential struct {
	Key   []byte // unique within the method
	Data  []byte // the method's own record
	Label string
}

// MethodResult is what a method's Verify found.
type MethodResult struct {
	User       UserID      // who the proof belongs to, when the flow didn't know
	Credential *Credential // to store, or to update
	Verified   bool        // the proof counts as two factors
	Unlinked   *Identity   // a valid identity that belongs to no user
	Address    string      // an address the proof shows control of (§5.7.2)
}

// AddressOnly is an optional interface of a Method whose proofs have
// nothing to guess, such as a signature over the server's challenge or a
// provider's code: answering true, its attempts count toward the client
// address's counter alone, or a trusted device's pair counter (§5.5.9).
type AddressOnly interface{ AddressOnly() bool }

// Identity is an identity a method proved, such as an OIDC subject.
type Identity struct {
	Issuer, Subject, Email string
	EmailVerified          bool
}

// Refuse is what a module's Verify returns for a proof it refuses. It
// wraps ErrBadCredentials and its Error() is fixed: the reason is in no
// message. reason is the event's Reason and matches [a-z][a-z0-9_]{0,31};
// any other is recorded as "refused". The engine answers the caller with
// plain ErrBadCredentials (§5.5).
func Refuse(reason string) error {
	if !reasonRE.MatchString(reason) {
		reason = "refused"
	}
	return refusal{reason}
}

var reasonRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

type refusal struct{ reason string }

func (refusal) Error() string    { return "auth: the method refused the proof" }
func (refusal) Unwrap() error    { return ErrBadCredentials }
func (r refusal) String() string { return r.Error() }
