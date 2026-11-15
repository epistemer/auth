package auth

import (
	"context"
	"log/slog"
)

// record gives an event to the Recorder, or to log/slog without one. The
// caller never puts a secret in it (§5.11.3).
func (a *Auth) record(ctx context.Context, e Event) {
	e.At = a.now()
	if e.Client == (Client{}) {
		e.Client = clientFrom(ctx)
	}
	if a.recorder != nil {
		a.recorder.Record(ctx, e)
		return
	}
	slog.InfoContext(ctx, "auth", "event", e.Kind, "user", string(e.User), "session", string(e.Session),
		"method", e.Method, "reason", e.Reason, "addr", e.Client.Addr.String())
}
