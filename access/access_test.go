package access_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth"
	"github.com/epistemer/auth/access"
	"github.com/epistemer/auth/authtest"
)

var (
	payoutApprove = access.Permission("payout.approve", "Approve payouts")
	reportView    = access.Permission("report.view", "View reports", auth.Unverified)
)

const pw = "orange tiger juggles 47 lamps"

func allowUnverified(context.Context, auth.User) auth.Policy {
	return auth.Policy{AllowUnverified: true}
}

type shop struct {
	*authtest.Kit
	ac  *access.Access
	t   *testing.T
	mux *http.ServeMux
}

// newShop has sara (u1) and omar (u2), with passwords and email addresses,
// and two routes: /payouts needs payout.approve, /reports report.view.
func newShop(t *testing.T) *shop {
	k := authtest.New(t, auth.WithPolicy(allowUnverified))
	ac, err := access.New(dbOf(t, k))
	if err != nil {
		t.Fatal(err)
	}
	s := &shop{Kit: k, ac: ac, t: t, mux: http.NewServeMux()}
	for _, u := range []struct{ login, id string }{{"sara", "u1"}, {"omar", "u2"}} {
		k.AddUser(u.login, auth.User{ID: auth.UserID(u.id), Name: u.login}, u.login+"@toyshop.example")
		if err := k.Auth.SetPassword(context.Background(), auth.UserID(u.id), pw); err != nil {
			t.Fatal(err)
		}
	}
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	web := k.Auth.Load(auth.Cookie())
	s.mux.Handle("/payouts", web(k.Auth.Require(ac.Can(payoutApprove))(ok)))
	s.mux.Handle("/reports", web(k.Auth.Require(ac.Can(reportView))(ok)))
	return s
}

// signIn returns a session cookie for login: verified with an emailed code
// as the second proof, or unverified with the password alone.
func (s *shop) signIn(login string, verified bool) *http.Cookie {
	s.t.Helper()
	ctx := context.Background()
	a := s.Auth
	f, err := a.SignIn(ctx, login, auth.Cookie())
	if err != nil {
		s.t.Fatal(err)
	}
	if f, err = a.Prove(ctx, f.Token, auth.Password(pw)); err != nil {
		s.t.Fatal(err)
	}
	if verified {
		s.Clock.Advance(time.Minute)
		if _, err := a.Challenge(ctx, f.Token, auth.MethodEmailCode); err != nil {
			s.t.Fatal(err)
		}
		m, _ := s.LastMessage(login + "@toyshop.example")
		if f, err = a.Prove(ctx, f.Token, auth.EmailCode(m.Code)); err != nil || !f.Verified {
			s.t.Fatalf("second proof: %+v %v", f, err)
		}
	}
	res, err := a.Finish(ctx, f.Token)
	if err != nil {
		s.t.Fatal(err)
	}
	w := httptest.NewRecorder()
	res.Write(w)
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-session" {
			return c
		}
	}
	s.t.Fatal("no session cookie")
	return nil
}

func (s *shop) get(path string, c *http.Cookie) int {
	r := httptest.NewRequest("GET", "https://shop.example"+path, nil)
	if c != nil {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)
	return w.Code
}

// §7, permissions: a user in a group granted p passes Can(p); after
// Withdraw or Leave the next request is refused (§5.10.2, §5.10.6).
func TestCan(t *testing.T) {
	s := newShop(t)
	ctx := context.Background()
	sara := s.signIn("sara", true)
	if code := s.get("/payouts", sara); code != http.StatusForbidden {
		t.Fatalf("before a grant: %d", code)
	}
	g, err := s.ac.CreateGroup(ctx, "Finance")
	if err != nil {
		t.Fatal(err)
	}
	s.ac.Grant(ctx, g.ID, payoutApprove)
	s.ac.Join(ctx, "u1", g.ID)
	if code := s.get("/payouts", sara); code != 200 {
		t.Fatalf("granted: %d", code)
	}
	s.ac.Withdraw(ctx, g.ID, payoutApprove)
	if code := s.get("/payouts", sara); code != http.StatusForbidden {
		t.Errorf("after Withdraw: %d", code)
	}
	s.ac.Grant(ctx, g.ID, payoutApprove)
	s.ac.Leave(ctx, "u1", g.ID)
	if code := s.get("/payouts", sara); code != http.StatusForbidden {
		t.Errorf("after Leave: %d", code)
	}
	if code := s.get("/payouts", nil); code != http.StatusUnauthorized {
		t.Errorf("without a session: %d", code)
	}
	if err := s.ac.Check(ctx, "u2", payoutApprove); !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("Check for a user in no group: %v", err)
	}
}

// §7, permissions: a permission declared without a level refuses an
// unverified session with ErrNotVerified; one declared Unverified admits
// it (§5.10.3).
func TestCanLevels(t *testing.T) {
	s := newShop(t)
	ctx := context.Background()
	g, _ := s.ac.CreateGroup(ctx, "Staff")
	s.ac.Grant(ctx, g.ID, payoutApprove)
	s.ac.Grant(ctx, g.ID, reportView)
	s.ac.Join(ctx, "u1", g.ID)
	weak := s.signIn("sara", false)
	if code := s.get("/payouts", weak); code != http.StatusForbidden {
		t.Errorf("an unverified session on a verified permission: %d", code)
	}
	if code := s.get("/reports", weak); code != 200 {
		t.Errorf("an unverified session on an Unverified permission: %d", code)
	}
	sess := &auth.Session{User: "u1"}
	if err := s.ac.Can(payoutApprove).Check(ctx, sess); !errors.Is(err, auth.ErrNotVerified) {
		t.Errorf("Can on an unverified session: %v", err)
	}
	sess.Verified = true
	if err := s.ac.Can(payoutApprove).Check(ctx, sess); err != nil {
		t.Errorf("Can on a verified session: %v", err)
	}
	if err := s.ac.Can(payoutApprove).Check(ctx, nil); !errors.Is(err, auth.ErrNoSession) {
		t.Errorf("Can without a session: %v", err)
	}
}

// §7, permissions: root holds a permission declared after it was made, and
// its last member can't leave or be removed. It can't be deleted or
// renamed (§5.10.4).
func TestRoot(t *testing.T) {
	s := newShop(t)
	ctx := context.Background()
	if err := s.ac.Join(ctx, "u1", access.Root); err != nil {
		t.Fatal(err)
	}
	later := access.Permission("shop.close", "Close the shop")
	t.Cleanup(func() { access.Undeclare(later) })
	if err := s.ac.Check(ctx, "u1", later); err != nil {
		t.Errorf("root and a permission declared later: %v", err)
	}
	if err := s.ac.Leave(ctx, "u1", access.Root); !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("root's last member left: %v", err)
	}
	if err := s.ac.RemoveUser(ctx, "u1"); !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("root's last member removed: %v", err)
	}
	if m, _ := s.ac.Members(ctx, access.Root); len(m) != 1 {
		t.Errorf("root's members %v", m)
	}
	s.ac.Join(ctx, "u2", access.Root)
	if err := s.ac.Leave(ctx, "u1", access.Root); err != nil {
		t.Errorf("one of two root members leaving: %v", err)
	}
	if err := s.ac.DeleteGroup(ctx, access.Root); !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("DeleteGroup(root): %v", err)
	}
	if err := s.ac.RenameGroup(ctx, access.Root, "Admins"); !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("RenameGroup(root): %v", err)
	}
	if ps, _ := s.ac.Granted(ctx, access.Root); !slices.Contains(ps, later) || !slices.Contains(ps, payoutApprove) {
		t.Error("Granted(root) isn't every permission")
	}
	gs, _ := s.ac.Groups(ctx)
	if len(gs) != 1 || gs[0].ID != access.Root || gs[0].Name != "Root" {
		t.Errorf("root after refused changes: %+v", gs)
	}
	if m, _ := s.ac.Members(ctx, access.Root); len(m) != 1 || m[0] != "u2" {
		t.Errorf("root's members: %v", m)
	}
}

// RemoveUser takes a user out of every group at once; a removal that would
// empty root changes nothing.
func TestRemoveUser(t *testing.T) {
	s := newShop(t)
	ctx := context.Background()
	a, _ := s.ac.CreateGroup(ctx, "A")
	b, _ := s.ac.CreateGroup(ctx, "B")
	s.ac.Join(ctx, "u1", a.ID)
	s.ac.Join(ctx, "u1", b.ID)
	s.ac.Join(ctx, "u2", access.Root)
	if err := s.ac.RemoveUser(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if gs, _ := s.ac.GroupsOf(ctx, "u1"); len(gs) != 0 {
		t.Errorf("groups after RemoveUser: %v", gs)
	}
	if m, _ := s.ac.Members(ctx, a.ID); len(m) != 0 {
		t.Errorf("members after RemoveUser: %v", m)
	}
	// Groups on both sides of "root" in key order, so the refusal comes
	// after some memberships were looked at, whatever the IDs drawn.
	var many []access.Group
	for i := range 8 {
		g, _ := s.ac.CreateGroup(ctx, string(rune('a'+i)))
		s.ac.Join(ctx, "u2", g.ID)
		many = append(many, g)
	}
	if err := s.ac.RemoveUser(ctx, "u2"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("removing root's last member: %v", err)
	}
	if gs, _ := s.ac.GroupsOf(ctx, "u2"); len(gs) != 9 {
		t.Errorf("a refused RemoveUser changed memberships: %d", len(gs))
	}
	for _, g := range many {
		if m, _ := s.ac.Members(ctx, g.ID); len(m) != 1 {
			t.Errorf("group %s lost u2: %v", g.Name, m)
		}
	}
}

// Groups, their names, members and grants; deleting one ends its
// memberships.
func TestGroups(t *testing.T) {
	s := newShop(t)
	ctx := context.Background()
	g, _ := s.ac.CreateGroup(ctx, "Finance")
	s.ac.RenameGroup(ctx, g.ID, "Accounts")
	s.ac.Join(ctx, "u1", g.ID)
	s.ac.Grant(ctx, g.ID, payoutApprove)
	gs, _ := s.ac.Groups(ctx)
	if len(gs) != 2 || gs[0].Name != "Accounts" || gs[1].ID != access.Root {
		t.Errorf("Groups: %+v", gs)
	}
	if m, _ := s.ac.Members(ctx, g.ID); len(m) != 1 || m[0] != "u1" {
		t.Errorf("Members: %v", m)
	}
	if ps, _ := s.ac.Granted(ctx, g.ID); len(ps) != 1 || ps[0] != payoutApprove {
		t.Errorf("Granted: %v", ps)
	}
	access.GrantUndeclared(s.ac, g.ID, "shop.gone")
	if err := s.ac.DeleteGroup(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	if stale, _ := s.ac.Stale(ctx); len(stale) != 0 {
		t.Errorf("a deleted group's grants stayed: %v", stale)
	}
	if gs, _ := s.ac.GroupsOf(ctx, "u1"); len(gs) != 0 {
		t.Errorf("memberships of a deleted group: %v", gs)
	}
	if err := s.ac.Check(ctx, "u1", payoutApprove); !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("a deleted group's grant: %v", err)
	}
	if err := s.ac.Join(ctx, "u1", "nope"); err == nil {
		t.Error("joined a group that doesn't exist")
	}
}

// A permission's key is permanent and declared once; its text is the i18n
// key permission.<key> (§5.10.1).
func TestPermissionDeclared(t *testing.T) {
	if payoutApprove.Key() != "payout.approve" || payoutApprove.T(context.Background()) != "Approve payouts" {
		t.Errorf("perm %q %q", payoutApprove.Key(), payoutApprove.T(context.Background()))
	}
	defer func() {
		if recover() == nil {
			t.Error("a key declared twice didn't panic")
		}
	}()
	access.Permission("payout.approve", "Again")
}

// §5.10.5: a grant whose key is no longer declared is ignored by checks,
// listed by Stale and never deleted.
func TestStale(t *testing.T) {
	s := newShop(t)
	ctx := context.Background()
	g, _ := s.ac.CreateGroup(ctx, "Old")
	s.ac.Join(ctx, "u1", g.ID)
	s.ac.Grant(ctx, g.ID, payoutApprove)
	gone := forgetPermission(t, s, g.ID, "shop.legacy")
	if err := s.ac.Check(ctx, "u1", gone); !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("an undeclared grant passed a check: %v", err)
	}
	stale, err := s.ac.Stale(ctx)
	if err != nil || strings.Join(stale, ",") != "shop.legacy" {
		t.Errorf("Stale: %v %v", stale, err)
	}
	if ps, _ := s.ac.Granted(ctx, g.ID); len(ps) != 1 || ps[0] != payoutApprove {
		t.Errorf("Granted: %v", ps)
	}
	// An undeclared handle grants, withdraws and passes nothing, and is
	// held to Verified.
	if err := s.ac.Grant(ctx, g.ID, gone); err == nil {
		t.Error("Grant of an undeclared handle")
	}
	if err := s.ac.Grant(ctx, g.ID, &access.Perm{}); err == nil {
		t.Error("Grant of a zero Perm")
	}
	if err := s.ac.Can(gone).Check(ctx, &auth.Session{User: "u1"}); !errors.Is(err, auth.ErrNotVerified) {
		t.Errorf("Can of an undeclared handle on an unverified session: %v", err)
	}
	if (&access.Perm{}).T(ctx) != "" {
		t.Error("a zero Perm's text")
	}
	if stale, _ := s.ac.Stale(ctx); len(stale) != 1 {
		t.Error("Stale's keys went away")
	}
}

// §5.10.6: Require answers ErrNoSession with 401 and the others with 403,
// through WithReject when the app set one.
func TestRequireStatuses(t *testing.T) {
	var got []error
	k := authtest.New(t, auth.WithPolicy(allowUnverified), auth.WithReject(func(w http.ResponseWriter, r *http.Request, err error) {
		got = append(got, err)
		w.WriteHeader(errors.KindOf(err).Status())
	}))
	ac, _ := access.New(dbOf(t, k))
	h := k.Auth.Load(auth.Cookie())(k.Auth.Require(ac.Can(payoutApprove))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "https://shop.example/payouts", nil))
	if w.Code != http.StatusUnauthorized || len(got) != 1 || !errors.Is(got[0], auth.ErrNoSession) {
		t.Errorf("without a session: %d %v", w.Code, got)
	}
	s := &shop{Kit: k, ac: ac, t: t}
	k.AddUser("sara", auth.User{ID: "u1", Name: "sara"}, "sara@toyshop.example")
	k.Auth.SetPassword(context.Background(), "u1", pw)
	for name, c := range map[string]struct {
		verified bool
		want     error
	}{"unverified": {false, auth.ErrNotVerified}, "verified without the grant": {true, auth.ErrForbidden}} {
		got = nil
		r := httptest.NewRequest("GET", "https://shop.example/payouts", nil)
		r.AddCookie(s.signIn("sara", c.verified))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || len(got) != 1 || !errors.Is(got[0], c.want) {
			t.Errorf("%s: %d %v", name, w.Code, got)
		}
	}
}

// dbOf opens a store for access beside the kit's: access needs only a
// bbolt file, and auth's kit keeps its own to itself.
func dbOf(t *testing.T, _ *authtest.Kit) *bolt.DB {
	t.Helper()
	db, err := bolt.Open(filepath.Join(t.TempDir(), "access.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func forgetPermission(t *testing.T, s *shop, g access.GroupID, key string) *access.Perm {
	t.Helper()
	p, err := access.GrantUndeclared(s.ac, g, key)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Leave and Withdraw refuse a group that doesn't exist.
func TestUnknownGroup(t *testing.T) {
	s := newShop(t)
	ctx := context.Background()
	if err := s.ac.Leave(ctx, "u1", "nope"); err == nil {
		t.Error("Leave of a group that doesn't exist")
	}
	if err := s.ac.Withdraw(ctx, "nope", payoutApprove); err == nil {
		t.Error("Withdraw from a group that doesn't exist")
	}
}

// customReq names no level, so the route keeps the Verified default,
// beside a permission that asks for less.
type customReq struct{}

func (customReq) Check(context.Context, *auth.Session) error { return nil }

// Review 0016, finding 1: combining requirements never loses the Verified
// default, and a named level is enforced by Require itself.
func TestCombinedLevels(t *testing.T) {
	s := newShop(t)
	ctx := context.Background()
	g, _ := s.ac.CreateGroup(ctx, "Staff")
	s.ac.Grant(ctx, g.ID, reportView)
	s.ac.Join(ctx, "u1", g.ID)
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	web := s.Auth.Load(auth.Cookie())
	s.mux.Handle("/mixed", web(s.Auth.Require(s.ac.Can(reportView), customReq{})(ok)))
	s.mux.Handle("/lying", web(s.Auth.Require(liar{})(ok)))
	weak := s.signIn("sara", false)
	if code := s.get("/mixed", weak); code != http.StatusForbidden {
		t.Errorf("an Unverified permission beside a requirement with no level: %d", code)
	}
	if code := s.get("/lying", weak); code != http.StatusForbidden {
		t.Errorf("a requirement claiming Verified it doesn't check: %d", code)
	}
	if code := s.get("/reports", weak); code != 200 {
		t.Errorf("the Unverified permission alone: %d", code)
	}
}

// liar names Verified but checks nothing.
type liar struct{}

func (liar) RequiredLevel() auth.Level                  { return auth.Verified }
func (liar) Check(context.Context, *auth.Session) error { return nil }
