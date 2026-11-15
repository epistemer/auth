package auth

import "context"

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
}

// Identity is an identity a method proved, such as an OIDC subject.
type Identity struct {
	Issuer, Subject, Email string
	EmailVerified          bool
}
