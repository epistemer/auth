package auth

import (
	"net/http"
	"strings"
	"testing"

	"github.com/epistemer/errors"
)

// Interface §4.6: each error's key and kind.
func TestErrorTable(t *testing.T) {
	for _, c := range []struct {
		err  interface{ K() string }
		key  string
		kind errors.Kind
	}{
		{ErrBadCredentials, "bad_credentials", errors.Unauthenticated},
		{ErrBadCode, "bad_code", errors.Unauthenticated},
		{ErrTooManyAttempts, "too_many_attempts", errors.RateLimited},
		{ErrFlowExpired, "flow_expired", errors.Invalid},
		{ErrNotReady, "not_ready", errors.Invalid},
		{ErrPasswordRequired, "password_required", errors.Invalid},
		{ErrMethodUnavailable, "method_unavailable", errors.Invalid},
		{ErrCannotVerify, "cannot_verify", errors.Forbidden},
		{ErrUserDisabled, "user_disabled", errors.Forbidden},
		{ErrNoSession, "no_session", errors.Unauthenticated},
		{ErrNotVerified, "not_verified", errors.Forbidden},
		{ErrStale, "stale", errors.Forbidden},
		{ErrForbidden, "forbidden", errors.Forbidden},
		{ErrPasswordTooShort, "password_too_short", errors.Invalid},
		{ErrPasswordTooLong, "password_too_long", errors.Invalid},
		{ErrPasswordCommon, "password_common", errors.Invalid},
		{ErrPasswordPersonal, "password_personal", errors.Invalid},
		{ErrPasswordSimple, "password_simple", errors.Invalid},
	} {
		if c.err.K() != "errors.auth."+c.key {
			t.Errorf("%s: key %s", c.key, c.err.K())
		}
		if k := c.err.(interface{ Kind() errors.Kind }).Kind(); k != c.kind {
			t.Errorf("%s: kind %v; want %v", c.key, k, c.kind)
		}
	}
	// A private error shows as errors.Unknown.
	if k := errors.Public(ErrNoUser).K(); k != "errors.unknown" {
		t.Errorf("ErrNoUser shows as %s", k)
	}
}

// §5.11.1: ending a session is an event, also when a password change or a
// new sign-in ends it.
func TestSessionEndedEvents(t *testing.T) {
	s := newShopKit(t, nil)
	idOf := func(c *http.Cookie) SessionID {
		return SessionID(strings.Fields(s.req("GET", "/who", c, nil).Body.String())[1])
	}
	old := s.signIn(t, "sara", goodPassword)
	oldID := idOf(old)
	w := s.req("POST", "/sign-in", old, map[string][]string{"login": {"sara"}, "password": {goodPassword}}, "Sec-Fetch-Site", "same-origin")
	curID := idOf(cookieOf(t, w, "__Host-session"))
	if err := s.SetPassword(s.ctx, "u1", "another long phrase 93 owls"); err != nil {
		t.Fatal(err)
	}
	want := map[string]SessionID{"signed_in_again": oldID, "password_changed": curID}
	for _, e := range s.events.all {
		if e.Kind != "session.ended" {
			continue
		}
		if id, ok := want[e.Reason]; !ok || e.Session != id || e.User != "u1" {
			t.Errorf("event %+v", e)
		}
		delete(want, e.Reason)
	}
	if len(want) != 0 {
		t.Errorf("missing session.ended events: %v", want)
	}
}
