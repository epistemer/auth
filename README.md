# auth

neozp's authentication package: sign-in flows, sessions, devices and
permissions.

The app owns its users. This package owns how they prove who they are:

- **One flow for every way in.** Signing in, stepping up, recovering an
  account, accepting an invitation and adding a factor all collect proofs in
  one engine, so throttling, audit events and protection against account
  enumeration exist once.
- **Proofs:** passwords (argon2id, with a strength estimate), emailed or
  texted codes and links, authenticator apps (TOTP) and recovery codes.
  Passkeys and OpenID Connect come as modules after `v0.1.0`.
- **Sessions that record what was proven.** A session is verified or
  unverified, and remembers when each proof was made. Routes need a verified
  one unless they say otherwise, and a dangerous action can ask for a recent
  proof.
- **Two carriers.** An opaque cookie for browsers, with the cross-origin
  check built in; for apps, a short-lived JWT access token that carries the
  app's claims and is refused the moment its session ends, with a rotating
  refresh token that ends the session when it is used twice.
- **Devices.** A device the user chose to remember can stand for the second
  proof, if the user's policy allows it.
- **Permissions** declared in code, with groups and memberships
  (`auth/access`).

It stores its data in the app's bbolt file, takes its configuration through a
getter interface ([cfgx](https://github.com/epistemer/cfgx)), and returns
errors people can read in their language
([errors](https://github.com/epistemer/errors),
[i18n](https://github.com/epistemer/i18n)). It sends no mail and renders no
page: the app's `Sender` delivers messages, and its handlers call the flows.

```sh
go get github.com/epistemer/auth
go get github.com/epistemer/auth/authschema # the cfgx schema fragment, for the app's settings
```

Before `v1.0.0` the API may still change; [CHANGELOG.md](CHANGELOG.md) says
how.

## Quickstart

The app gives auth its store, its config, a `Directory` that finds users by
login, and a `Sender`:

```go
a, err := auth.New(db, settings, directory, mailer,
	auth.WithPolicy(func(ctx context.Context, u auth.User) auth.Policy {
		if isStaff(ctx, u) {
			return auth.Policy{} // two proofs, every time, on every device
		}
		return auth.Policy{AllowUnverified: true, TrustDevices: true}
	}),
)
```

Every route goes through `Load`, which reads the session and refuses forged
cross-origin requests; `Require` says what a route needs:

```go
web := a.Load(auth.Cookie())
mux.Handle("POST /sign-in", web(signIn))
mux.Handle("GET /orders", web(a.Require(auth.Unverified)(orders)))
mux.Handle("POST /payouts/{id}/approve",
	web(a.Require(ac.Can(PayoutApprove), auth.Within(5*time.Minute))(approve)))
mux.Handle("/api/", a.Load(auth.Bearer())(a.Require()(api)))
```

A sign-in collects proofs until the policy is met. Every error is one people
can read (`errors.T(ctx, err)`), with the status its kind gives:

```go
flow, err := a.SignIn(ctx, login, auth.Cookie())
if err == nil {
	flow, err = a.Prove(ctx, flow.Token, auth.Password(pw))
}
if err != nil {
	fail(w, r, err) // a wrong password and an unknown login answer alike
	return
}
if !flow.Ready {
	// flow.Offers lists the second proofs this user can give.
	if slices.Contains(flow.Offers, auth.MethodEmailCode) {
		if _, err := a.Challenge(ctx, flow.Token, auth.MethodEmailCode); err != nil {
			fail(w, r, err)
			return
		}
	}
	flow.Write(w) // the next request reads auth.FlowToken(ctx) and proves one
	return
}
res, err := a.Finish(ctx, flow.Token)
if err != nil {
	fail(w, r, err)
	return
}
res.Write(w) // the session cookie
```

The runnable examples on [pkg.go.dev](https://pkg.go.dev/github.com/epistemer/auth)
cover signing in, stepping up, recovery and permissions, and
[examples/shop](examples/shop) is a whole app: web and API sign-in, a step-up
before payouts, and an end-to-end test.

## What's not in v0.1

Passkeys and OpenID Connect (modules after `v0.1.0`), permissions on single
resources, API keys for machines, a breach-corpus lookup, drawing QR codes,
handlers and pages, and signing in by emailed link alone.

## Where to read

| | |
|---|---|
| [docs/interface.md](docs/interface.md) | The contract: what an app writes and gets back, and every rule |
| [docs/adr/0001-one-flow.md](docs/adr/0001-one-flow.md) | The design and the options it rejected |
| [docs/api-review.md](docs/api-review.md) | Every exported identifier against the contract, and the test that pins it |
| [docs/roadmap.md](docs/roadmap.md) | The order of work and what counts as done |
| [docs/status.md](docs/status.md) | What happened in each working session |
| [docs/reviews](docs/reviews) | Every cross-model review and what was done with each finding |

## License

MIT
