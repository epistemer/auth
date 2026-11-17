// Command shop runs the toy shop: auth's example app.
//
//	SHOP_AUTH_ISSUER=toyshop SHOP_AUTH_SECRET=$(openssl rand -hex 32) \
//	SHOP_AUTH_PASSKEY_DOMAIN=localhost SHOP_AUTH_PASSKEY_ORIGINS=http://localhost:8080 \
//	SHOP_AUTH_COOKIE_INSECURE=true \
//	SHOP_DEMO_PASSWORD='a long phrase of your own' SHOP_DEMO_MAIL=$(mktemp -d) go run .
//
// Passkeys are bound to a domain; on your own machine it is localhost, over
// plain HTTP, which browsers allow for localhost alone.
//
// With SHOP_DEMO_PASSWORD set it seeds sara@toyshop.example, a member of
// root, with that password. With SHOP_DEMO_MAIL set to a directory, mail is
// written there, one file a message, so you can read the codes.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth"
	"github.com/epistemer/auth/access"
	"github.com/epistemer/auth/examples/shop/internal/settings"
	"github.com/epistemer/auth/examples/shop/internal/shop"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx); err != nil {
		slog.Error("shop", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	cfg, err := settings.LoadServe(ctx)
	if err != nil {
		return err
	}
	db, err := bolt.Open(cfg.ServerStore(), 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return err
	}
	defer db.Close()
	dir := shop.NewDirectory()
	dir.Add("u1", "sara@toyshop.example", "Sara", "sara@toyshop.example")
	var out auth.Sender = shop.NewOutbox()
	if d := os.Getenv("SHOP_DEMO_MAIL"); d != "" {
		out = mailbox(d)
	}
	s, err := shop.New(db, cfg, dir, out)
	if err != nil {
		return err
	}
	if pw := os.Getenv("SHOP_DEMO_PASSWORD"); pw != "" {
		if err := s.Auth.SetPassword(ctx, "u1", pw); err != nil {
			return err
		}
		if err := s.Access.Join(ctx, "u1", access.Root); err != nil {
			return err
		}
	}

	// Everything below stops when ctx ends or the server fails, and run
	// returns only once requests have drained and the sweeper has stopped,
	// so db.Close comes last.
	// Deferred calls run last first: cancel, then Wait.
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// A Sweep at start, then hourly, removes what has expired.
	wg.Go(func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			if err := s.Auth.Sweep(ctx); err != nil && ctx.Err() == nil {
				slog.Error("shop: sweep", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	})
	srv := &http.Server{Addr: cfg.ServerAddr(), Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	stopped := make(chan error, 1)
	wg.Go(func() {
		<-ctx.Done()
		shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		stopped <- srv.Shutdown(shutdown)
	})
	slog.Info("shop: listening", "addr", cfg.ServerAddr())
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return <-stopped
}

// mailbox delivers each message to a file of its own in a directory, for a
// demo on your machine: a real shop renders it and hands it to its mailer.
// Never log a message: it carries a code or a link.
type mailbox string

func (d mailbox) Send(_ context.Context, m auth.Message) error {
	body := fmt.Sprintf("To: %s\nCode: %s\nToken: %s\n", m.To, m.Code, m.Token)
	name := filepath.Join(string(d), fmt.Sprintf("%d-%d.txt", time.Now().UnixNano(), m.Kind))
	return os.WriteFile(name, []byte(body), 0o600)
}
