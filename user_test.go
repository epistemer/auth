package auth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/store"
)

// §4.5: DeleteUser removes everything auth holds for a user, and nothing of
// anyone else's. Every bucket but the throttle's digests and the layout
// version is read for the user's ID and session IDs afterwards.
func TestDeleteUser(t *testing.T) {
	const sara, omar UserID = "sara-3f9c2a71", "omar-8b14d0e6"
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: sara, Name: "sara"}, goodPassword, saraMail)
	k.addUser(t, "omar", User{ID: omar, Name: "omar"}, goodPassword, "omar@toyshop.example")
	bearer := func(login string) Result {
		t.Helper()
		f, err := k.SignIn(k.ctx, login, Bearer())
		if err == nil {
			_, err = k.Prove(k.ctx, f.Token, Password(goodPassword))
		}
		if err != nil {
			t.Fatal(err)
		}
		res, err := k.Finish(k.ctx, f.Token)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	// Sara: a session left idle past session.idle, not yet swept;
	idle := bearer("sara")
	k.clock.advance(25 * time.Hour)
	// a cookie session on a remembered device, a bearer session
	// refreshed once, an ended session, an authenticator app, a flow under
	// way, an invitation and a recovery link.
	web := twoFactorSignIn(t, k, nil, RememberDevice("laptop"))
	api := bearer("sara")
	next, err := k.Refresh(k.ctx, api.Refresh)
	if err != nil {
		t.Fatal(err)
	}
	gone := bearer("sara")
	if err := k.Revoke(k.ctx, sara, gone.Session.ID); err != nil {
		t.Fatal(err)
	}
	k.addTOTP(t, sara, "phone")
	pending := passwordOnly(t, k, "sara")
	invitation, err := k.Invite(k.ctx, sara)
	if err != nil {
		t.Fatal(err)
	}
	k.clock.advance(time.Minute)
	rf, err := k.Recover(k.ctx, "sara")
	if err == nil {
		_, err = k.Challenge(k.ctx, rf.Token, MethodEmailLink)
	}
	if err != nil {
		t.Fatal(err)
	}
	link := k.lastMessage(t, saraMail).Token
	// A second recovery, followed and ready to set a password.
	k.clock.advance(time.Minute)
	rf2, err := k.Recover(k.ctx, "sara")
	if err == nil {
		_, err = k.Challenge(k.ctx, rf2.Token, MethodEmailLink)
	}
	if err != nil {
		t.Fatal(err)
	}
	followed, err := k.Follow(k.ctx, k.lastMessage(t, saraMail).Token)
	if err != nil {
		t.Fatal(err)
	}
	// Omar: a cookie session on a remembered device, a bearer session, a
	// flow under way and an invitation.
	of, err := k.SignIn(k.ctx, "omar", Cookie())
	if err == nil {
		of, err = k.Prove(k.ctx, of.Token, Password(goodPassword))
	}
	if err == nil {
		_, err = k.Challenge(k.ctx, of.Token, MethodEmailCode)
	}
	if err == nil {
		of, err = k.Prove(k.ctx, of.Token, EmailCode(k.lastCode(t, "omar@toyshop.example")))
	}
	var omarWeb Result
	if err == nil {
		omarWeb, err = k.Finish(k.ctx, of.Token, RememberDevice("omar's laptop"))
	}
	if err != nil || omarWeb.Session.Device == "" {
		t.Fatalf("omar's sign-in: %+v %v", omarWeb, err)
	}
	omarAPI := bearer("omar")
	omarFlow := passwordOnly(t, k, "omar")
	omarInvitation, err := k.Invite(k.ctx, omar)
	if err != nil {
		t.Fatal(err)
	}

	// An index entry whose session record is gone, as a crash could leave.
	err = k.db.Update(func(tx *bolt.Tx) error {
		return store.B(tx, store.SessionsByUser).Put(store.Key([]byte(sara), []byte("orphan")), nil)
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := k.DeleteUser(k.ctx, sara); err != nil {
		t.Fatal(err)
	}

	if web.Session.Device == "" {
		t.Fatal("sara's device wasn't registered")
	}
	marks := [][]byte{[]byte(sara), []byte(web.Session.ID), []byte(api.Session.ID), []byte(gone.Session.ID), []byte(idle.Session.ID), []byte(web.Session.Device)}
	omarLeft := 0
	err = k.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(store.Root).ForEachBucket(func(name []byte) error {
			if bytes.Equal(name, store.Throttle) || bytes.Equal(name, store.Meta) {
				return nil
			}
			return tx.Bucket(store.Root).Bucket(name).ForEach(func(key, v []byte) error {
				for _, m := range marks {
					if bytes.Contains(key, m) || bytes.Contains(v, m) {
						t.Errorf("%s still holds %q", name, m)
					}
				}
				if bytes.Contains(key, []byte(omar)) || bytes.Contains(v, []byte(omar)) {
					omarLeft++
				}
				return nil
			})
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if omarLeft == 0 {
		t.Error("omar's records went too")
	}

	// What Sara held signs no one in.
	if code, _ := k.api(t, next.Access); code != http.StatusUnauthorized {
		t.Errorf("sara's access token: %d", code)
	}
	if _, err := k.Refresh(k.ctx, next.Refresh); !errors.Is(err, ErrNoSession) {
		t.Errorf("sara's refresh token: %v", err)
	}
	r := httptest.NewRequest("GET", "https://shop.example/me", nil)
	r.AddCookie(&http.Cookie{Name: cookieName("session", false), Value: web.cookie})
	var found bool
	k.Load(Cookie())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, found = From(r.Context())
	})).ServeHTTP(httptest.NewRecorder(), r)
	if found {
		t.Error("sara's cookie still signs her in")
	}
	if _, err := k.Flow(k.ctx, pending.Token); !errors.Is(err, ErrFlowExpired) {
		t.Errorf("sara's flow: %v", err)
	}
	if _, err := k.Accept(k.ctx, invitation); err == nil {
		t.Error("sara's invitation was accepted")
	}
	if _, err := k.Follow(k.ctx, link); err == nil {
		t.Error("sara's recovery link was followed")
	}
	// A recovery under way can't set a password once she's gone.
	if _, err := k.Finish(k.ctx, followed.Token, NewPassword("violet engine sings 93 rivers")); err == nil {
		t.Error("a recovery under way set a password")
	}
	if fs, err := k.Factors(k.ctx, sara); err != nil || len(fs) != 0 {
		t.Errorf("sara's factors: %v %v", fs, err)
	}

	// Omar's are untouched: his password, his device, his sessions.
	if f := passwordOnly(t, k, "omar"); !f.Ready {
		t.Errorf("omar's password: %+v", f)
	}
	if ds, err := k.Devices(k.ctx, omar); err != nil || len(ds) != 1 {
		t.Errorf("omar's devices: %v %v", ds, err)
	}
	if ss, err := k.Sessions(k.ctx, omar); err != nil || len(ss) != 2 {
		t.Errorf("omar's sessions: %v %v", ss, err)
	}
	if _, err := k.Refresh(k.ctx, omarAPI.Refresh); err != nil {
		t.Errorf("omar's refresh token: %v", err)
	}
	if _, err := k.Flow(k.ctx, omarFlow.Token); err != nil {
		t.Errorf("omar's flow: %v", err)
	}
	if _, err := k.Accept(k.ctx, omarInvitation); err != nil {
		t.Errorf("omar's invitation: %v", err)
	}

	// One session.ended for each session that was live, none for the one
	// ended or the one gone idle, and one user.deleted.
	ended := map[SessionID]int{}
	deleted := 0
	k.events.mu.Lock()
	for _, e := range k.events.all {
		if e.Kind == "session.ended" && e.Reason == "user_deleted" && e.User == sara {
			ended[e.Session]++
		}
		if e.Kind == "user.deleted" && e.User == sara {
			deleted++
		}
	}
	k.events.mu.Unlock()
	if len(ended) != 2 || ended[web.Session.ID] != 1 || ended[api.Session.ID] != 1 || deleted != 1 {
		t.Errorf("events: session.ended %v, user.deleted %d", ended, deleted)
	}

	if err := k.DeleteUser(k.ctx, ""); err == nil {
		t.Error("DeleteUser of an empty ID")
	}
	if err := k.DeleteUser(k.ctx, sara); err != nil {
		t.Errorf("DeleteUser again: %v", err)
	}
}
