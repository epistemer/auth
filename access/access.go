// Package access is auth's permissions: permissions declared in code,
// groups and memberships kept in bbolt (interface §4.7, §5.10).
//
//	var PayoutApprove = access.Permission("payout.approve", "Approve payouts")
//	ac, err := access.New(db)
//	mux.Handle("POST /payouts/{id}/approve", web(a.Require(ac.Can(PayoutApprove))(approve)))
//
// A user holds a permission when a group they belong to was granted it.
// The group root holds every declared permission.
package access

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/epistemer/errors"
	"github.com/epistemer/i18n"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"github.com/epistemer/auth"
	"github.com/epistemer/auth/internal/secrets"
	"github.com/epistemer/auth/internal/storepb"
)

// Perm is a declared permission.
type Perm struct {
	key   string
	level auth.Level
	label i18n.TKer
}

var (
	mu       sync.Mutex
	declared = map[string]*Perm{}
)

// Permission declares a permission. Its key is permanent. It needs a
// verified session unless level says otherwise. Its text is the i18n key
// permission.<key>. Declaring a key twice panics (§5.10.1). Declare
// permissions in package-level variables.
func Permission(key, text string, level ...auth.Level) *Perm {
	if key == "" || strings.ContainsRune(key, 0) {
		panic("access: a permission key is empty or holds a zero byte")
	}
	if len(level) > 1 {
		panic(fmt.Sprintf("access: Permission(%q) with more than one level", key))
	}
	mu.Lock()
	defer mu.Unlock()
	if declared[key] != nil {
		panic(fmt.Sprintf("access: permission %q declared twice", key))
	}
	p := &Perm{key: key, level: auth.Verified, label: i18n.Key("permission."+key, text)}
	if len(level) == 1 {
		p.level = level[0]
	}
	declared[key] = p
	return p
}

// Key returns the permission's key.
func (p *Perm) Key() string { return p.key }

// T returns the permission's text in ctx's locale; "" for a handle that
// wasn't declared.
func (p *Perm) T(ctx context.Context, args ...any) string {
	if p == nil || p.label == nil {
		return ""
	}
	return p.label.T(ctx, args...)
}

// declaredPerm reports whether p is the handle Permission returned for its
// key: no other handle grants, withdraws or passes anything.
func declaredPerm(p *Perm) bool { return p != nil && lookup(p.key) == p }

// Permissions returns every declared permission, by key.
func Permissions() []*Perm {
	mu.Lock()
	defer mu.Unlock()
	out := make([]*Perm, 0, len(declared))
	for _, p := range declared {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b *Perm) int { return strings.Compare(a.key, b.key) })
	return out
}

func lookup(key string) *Perm {
	mu.Lock()
	defer mu.Unlock()
	return declared[key]
}

// GroupID identifies a group.
type GroupID string

// Root is the group that holds every declared permission (§5.10.4).
const Root GroupID = "root"

// Group is a group of users.
type Group struct {
	ID   GroupID
	Name string
}

// The layout under the top-level bucket auth_access (ADR 0005).
var (
	top         = []byte("auth_access")
	groupsB     = []byte("groups")      // <id> -> AccessGroup
	grantsB     = []byte("grants")      // <group>\x00<perm key> -> empty
	membersB    = []byte("members")     // <group>\x00<user> -> empty
	userGroupsB = []byte("user_groups") // <user>\x00<group> -> empty
)

// Access is the package's entry point. It is safe for concurrent use.
type Access struct {
	db  *bolt.DB
	now func() time.Time
}

// New returns an Access over db, the file auth uses, and makes the group
// root if it isn't there.
func New(db *bolt.DB) (*Access, error) {
	if db == nil {
		return nil, errors.New("access: New needs a database")
	}
	ac := &Access{db: db, now: time.Now}
	err := db.Update(func(tx *bolt.Tx) error {
		t, err := tx.CreateBucketIfNotExists(top)
		if err != nil {
			return err
		}
		for _, name := range [][]byte{groupsB, grantsB, membersB, userGroupsB} {
			if _, err := t.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		if b(tx, groupsB).Get([]byte(Root)) != nil {
			return nil
		}
		return put(tx, groupsB, []byte(Root), &storepb.AccessGroup{Id: string(Root), Name: "Root", Created: ac.now().UnixNano()})
	})
	if err != nil {
		return nil, fmt.Errorf("access: %w", err)
	}
	return ac, nil
}

func b(tx *bolt.Tx, name []byte) *bolt.Bucket { return tx.Bucket(top).Bucket(name) }

func put(tx *bolt.Tx, bucket, k []byte, m proto.Message) error {
	v, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return err
	}
	return b(tx, bucket).Put(k, v)
}

func pair(a, c string) []byte { return append(append([]byte(a), 0), c...) }

// keysUnder returns the second parts of the keys under first\x00.
func keysUnder(tx *bolt.Tx, bucket []byte, first string) []string {
	prefix := pair(first, "")
	var out []string
	c := b(tx, bucket).Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		out = append(out, string(k[len(prefix):]))
	}
	return out
}

// requirement is Can(p): a session, p's level, then p.
type requirement struct {
	ac *Access
	p  *Perm
}

// RequiredLevel names the permission's level to auth.Require (§5.10.3);
// a handle that wasn't declared is held to Verified.
func (r requirement) RequiredLevel() auth.Level {
	if !declaredPerm(r.p) {
		return auth.Verified
	}
	return r.p.level
}

func (r requirement) Check(ctx context.Context, s *auth.Session) error {
	if s == nil {
		return auth.ErrNoSession
	}
	if err := r.RequiredLevel().Check(ctx, s); err != nil {
		return err
	}
	return r.ac.Check(ctx, s.User, r.p)
}

// Can is a Requirement: a session, the level p declares, and p. It returns
// ErrNoSession, ErrNotVerified or ErrForbidden (§5.10.3).
func (ac *Access) Can(p *Perm) auth.Requirement {
	if ac == nil || p == nil {
		panic("access: Can with a nil Access or permission")
	}
	return requirement{ac, p}
}

// Check reports whether a user holds p: nil, or ErrForbidden. Only the
// permission is checked, not a session; a user in root holds every declared
// permission.
func (ac *Access) Check(ctx context.Context, id auth.UserID, p *Perm) error {
	if !declaredPerm(p) {
		return auth.ErrForbidden
	}
	held := false
	err := ac.db.View(func(tx *bolt.Tx) error {
		for _, g := range keysUnder(tx, userGroupsB, string(id)) {
			if GroupID(g) == Root || b(tx, grantsB).Get(pair(g, p.key)) != nil {
				held = true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !held {
		return auth.ErrForbidden
	}
	return nil
}

var (
	errUndeclared = errors.New("access: a permission that wasn't declared")
	errNoGroup    = errors.New("access: no such group")
	errRoot       = errors.New("access: the group root can't be changed so")
	errLastRoot   = errors.New("access: root's last member can't leave")
)

func groupExists(tx *bolt.Tx, id GroupID) bool { return b(tx, groupsB).Get([]byte(id)) != nil }

// CreateGroup makes a group.
func (ac *Access) CreateGroup(ctx context.Context, name string) (Group, error) {
	g := Group{ID: GroupID(secrets.NewID()), Name: name}
	err := ac.db.Update(func(tx *bolt.Tx) error {
		return put(tx, groupsB, []byte(g.ID), &storepb.AccessGroup{Id: string(g.ID), Name: name, Created: ac.now().UnixNano()})
	})
	return g, err
}

// RenameGroup renames a group; root can't be renamed.
func (ac *Access) RenameGroup(ctx context.Context, id GroupID, name string) error {
	if id == Root {
		return auth.ErrForbidden.Wrap(errRoot)
	}
	return ac.db.Update(func(tx *bolt.Tx) error {
		var g storepb.AccessGroup
		v := b(tx, groupsB).Get([]byte(id))
		if v == nil {
			return errNoGroup
		}
		if err := proto.Unmarshal(v, &g); err != nil {
			return err
		}
		g.Name = name
		return put(tx, groupsB, []byte(id), &g)
	})
}

// DeleteGroup removes a group, its grants and its memberships; root can't
// be deleted.
func (ac *Access) DeleteGroup(ctx context.Context, id GroupID) error {
	if id == Root {
		return auth.ErrForbidden.Wrap(errRoot)
	}
	return ac.db.Update(func(tx *bolt.Tx) error {
		if !groupExists(tx, id) {
			return errNoGroup
		}
		for _, p := range keysUnder(tx, grantsB, string(id)) {
			if err := b(tx, grantsB).Delete(pair(string(id), p)); err != nil {
				return err
			}
		}
		for _, u := range keysUnder(tx, membersB, string(id)) {
			if err := b(tx, membersB).Delete(pair(string(id), u)); err != nil {
				return err
			}
			if err := b(tx, userGroupsB).Delete(pair(u, string(id))); err != nil {
				return err
			}
		}
		return b(tx, groupsB).Delete([]byte(id))
	})
}

// Grant gives a group a permission.
func (ac *Access) Grant(ctx context.Context, id GroupID, p *Perm) error {
	if !declaredPerm(p) {
		return errUndeclared
	}
	return ac.db.Update(func(tx *bolt.Tx) error {
		if !groupExists(tx, id) {
			return errNoGroup
		}
		return b(tx, grantsB).Put(pair(string(id), p.key), nil)
	})
}

// Withdraw takes a permission back from a group.
func (ac *Access) Withdraw(ctx context.Context, id GroupID, p *Perm) error {
	if !declaredPerm(p) {
		return errUndeclared
	}
	return ac.db.Update(func(tx *bolt.Tx) error {
		if !groupExists(tx, id) {
			return errNoGroup
		}
		return b(tx, grantsB).Delete(pair(string(id), p.key))
	})
}

// Join adds a user to a group.
func (ac *Access) Join(ctx context.Context, u auth.UserID, id GroupID) error {
	if u == "" || strings.ContainsRune(string(u), 0) {
		return errors.New("access: a user ID is empty or holds a zero byte")
	}
	return ac.db.Update(func(tx *bolt.Tx) error {
		if !groupExists(tx, id) {
			return errNoGroup
		}
		if err := b(tx, membersB).Put(pair(string(id), string(u)), nil); err != nil {
			return err
		}
		return b(tx, userGroupsB).Put(pair(string(u), string(id)), nil)
	})
}

// Leave takes a user out of a group; root's last member can't leave.
func (ac *Access) Leave(ctx context.Context, u auth.UserID, id GroupID) error {
	return ac.db.Update(func(tx *bolt.Tx) error {
		if !groupExists(tx, id) {
			return errNoGroup
		}
		return leave(tx, u, id)
	})
}

func leave(tx *bolt.Tx, u auth.UserID, id GroupID) error {
	if b(tx, membersB).Get(pair(string(id), string(u))) == nil {
		// Not a member; clear a reverse entry left without one.
		return b(tx, userGroupsB).Delete(pair(string(u), string(id)))
	}
	if id == Root && len(keysUnder(tx, membersB, string(Root))) == 1 {
		return auth.ErrForbidden.Wrap(errLastRoot)
	}
	if err := b(tx, membersB).Delete(pair(string(id), string(u))); err != nil {
		return err
	}
	return b(tx, userGroupsB).Delete(pair(string(u), string(id)))
}

// RemoveUser takes a user out of every group, as one change: if they are
// root's last member, nothing changes. Call it before auth's DeleteUser.
func (ac *Access) RemoveUser(ctx context.Context, u auth.UserID) error {
	return ac.db.Update(func(tx *bolt.Tx) error {
		for _, g := range keysUnder(tx, userGroupsB, string(u)) {
			if err := leave(tx, u, GroupID(g)); err != nil {
				return err
			}
		}
		return nil
	})
}

// Groups returns every group, by name.
func (ac *Access) Groups(ctx context.Context) ([]Group, error) {
	var out []Group
	err := ac.db.View(func(tx *bolt.Tx) error {
		return b(tx, groupsB).ForEach(func(_, v []byte) error {
			var g storepb.AccessGroup
			if err := proto.Unmarshal(v, &g); err != nil {
				return err
			}
			out = append(out, Group{ID: GroupID(g.Id), Name: g.Name})
			return nil
		})
	})
	slices.SortFunc(out, func(a, c Group) int { return strings.Compare(a.Name, c.Name) })
	return out, err
}

// GroupsOf returns the groups a user belongs to, by name.
func (ac *Access) GroupsOf(ctx context.Context, u auth.UserID) ([]Group, error) {
	var out []Group
	err := ac.db.View(func(tx *bolt.Tx) error {
		for _, id := range keysUnder(tx, userGroupsB, string(u)) {
			var g storepb.AccessGroup
			v := b(tx, groupsB).Get([]byte(id))
			if v == nil {
				continue
			}
			if err := proto.Unmarshal(v, &g); err != nil {
				return err
			}
			out = append(out, Group{ID: GroupID(g.Id), Name: g.Name})
		}
		return nil
	})
	slices.SortFunc(out, func(a, c Group) int { return strings.Compare(a.Name, c.Name) })
	return out, err
}

// Members returns a group's members.
func (ac *Access) Members(ctx context.Context, id GroupID) ([]auth.UserID, error) {
	var out []auth.UserID
	err := ac.db.View(func(tx *bolt.Tx) error {
		if !groupExists(tx, id) {
			return errNoGroup
		}
		for _, u := range keysUnder(tx, membersB, string(id)) {
			out = append(out, auth.UserID(u))
		}
		return nil
	})
	return out, err
}

// Granted returns the declared permissions a group was granted: for root,
// every declared one. Grants of keys no longer declared are left out; Stale
// lists them.
func (ac *Access) Granted(ctx context.Context, id GroupID) ([]*Perm, error) {
	if id == Root {
		return Permissions(), nil
	}
	var out []*Perm
	err := ac.db.View(func(tx *bolt.Tx) error {
		if !groupExists(tx, id) {
			return errNoGroup
		}
		for _, k := range keysUnder(tx, grantsB, string(id)) {
			if p := lookup(k); p != nil {
				out = append(out, p)
			}
		}
		return nil
	})
	return out, err
}

// Stale returns the granted keys no longer declared, sorted (§5.10.5). The
// package never deletes them.
func (ac *Access) Stale(ctx context.Context) ([]string, error) {
	seen := map[string]bool{}
	err := ac.db.View(func(tx *bolt.Tx) error {
		return b(tx, grantsB).ForEach(func(k, _ []byte) error {
			_, key, _ := bytes.Cut(k, []byte{0})
			if lookup(string(key)) == nil {
				seen[string(key)] = true
			}
			return nil
		})
	})
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	slices.Sort(out)
	return out, err
}
