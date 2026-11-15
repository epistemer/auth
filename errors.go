package auth

import "github.com/epistemer/errors"

// The errors people see (interface §4.6). Each is an i18n key under
// errors.auth, so a deployment can translate and edit its text.
var (
	ErrBadCredentials    = errors.Key("errors.auth.bad_credentials", "the login or the password is wrong", errors.Unauthenticated)
	ErrBadCode           = errors.Key("errors.auth.bad_code", "the code or the link is wrong, used or expired", errors.Unauthenticated)
	ErrTooManyAttempts   = errors.Key("errors.auth.too_many_attempts", "too many attempts; try again later", errors.RateLimited)
	ErrFlowExpired       = errors.Key("errors.auth.flow_expired", "this sign-in has expired; start again", errors.Invalid)
	ErrNotReady          = errors.Key("errors.auth.not_ready", "another proof is needed first", errors.Invalid)
	ErrPasswordRequired  = errors.Key("errors.auth.password_required", "a new password is needed", errors.Invalid)
	ErrMethodUnavailable = errors.Key("errors.auth.method_unavailable", "that way of signing in isn't available here", errors.Invalid)
	ErrCannotVerify      = errors.Key("errors.auth.cannot_verify", "this account has no second way to prove who you are", errors.Forbidden)
	ErrUserDisabled      = errors.Key("errors.auth.user_disabled", "this account is disabled", errors.Forbidden)
	ErrNoSession         = errors.Key("errors.auth.no_session", "you need to sign in", errors.Unauthenticated)
	ErrNotVerified       = errors.Key("errors.auth.not_verified", "this needs a verified session", errors.Forbidden)
	ErrStale             = errors.Key("errors.auth.stale", "this needs a recent proof of who you are", errors.Forbidden)
	ErrForbidden         = errors.Key("errors.auth.forbidden", "you aren't allowed to do this", errors.Forbidden)

	ErrPasswordTooShort = errors.Key1[int]("errors.auth.password_too_short", "the password needs at least %d characters", errors.Invalid)
	ErrPasswordTooLong  = errors.Key("errors.auth.password_too_long", "the password is longer than 1024 bytes", errors.Invalid)
	ErrPasswordCommon   = errors.Key("errors.auth.password_common", "the password is made of common passwords, words or names", errors.Invalid)
	ErrPasswordPersonal = errors.Key("errors.auth.password_personal", "the password contains your name, login or address", errors.Invalid)
	ErrPasswordSimple   = errors.Key("errors.auth.password_simple", "the password is a simple pattern", errors.Invalid)
)
