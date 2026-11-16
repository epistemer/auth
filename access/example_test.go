package access_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth"
	"github.com/epistemer/auth/access"
)

// Permissions are declared once, at package level. Each is an i18n key,
// permission.<key>, so an admin page shows its text in the viewer's
// language. One that needs no verified session says so.
var (
	RefundIssue = access.Permission("example.refund.issue", "Issue refunds")
	StockView   = access.Permission("example.stock.view", "View stock", auth.Unverified)
)

// Groups hold permissions and users. Routes ask with Can, inside
// auth's Require: a.Require(ac.Can(RefundIssue)). Other code asks with
// Check.
func Example() {
	dir, _ := os.MkdirTemp("", "access-example")
	defer os.RemoveAll(dir)
	db, err := bolt.Open(filepath.Join(dir, "shop.db"), 0o600, nil)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	ac, err := access.New(db)
	if err != nil {
		panic(err)
	}
	ctx := context.Background()

	support, _ := ac.CreateGroup(ctx, "Support")
	_ = ac.Grant(ctx, support.ID, RefundIssue)
	_ = ac.Join(ctx, "u2", support.ID)
	_ = ac.Join(ctx, "u1", access.Root) // root holds every permission

	fmt.Println("u1 refunds:", ac.Check(ctx, "u1", RefundIssue) == nil)
	fmt.Println("u2 refunds:", ac.Check(ctx, "u2", RefundIssue) == nil)
	fmt.Println("u2 stock:", ac.Check(ctx, "u2", StockView) == nil)
	fmt.Println("u3 refunds:", ac.Check(ctx, "u3", RefundIssue))
	// Output:
	// u1 refunds: true
	// u2 refunds: true
	// u2 stock: false
	// u3 refunds: you aren't allowed to do this
}
