// Package authschema declares auth's settings for a cfgx app, so every app
// declares them the same way (interface §4.8):
//
//	var Auth = authschema.Group()
//	var Serve = dsl.Command("Serve").Uses(Auth /* , … */)
//
// The generated *settings.Serve then satisfies auth.Config. With passkeys,
// nest their group in it, and the settings satisfy passkey.Config too:
//
//	var Auth = authschema.Group(authschema.Passkey())
//
// The group is
// pinned with GoName("Auth"), and no key name holds an initialism, so the
// getter names don't depend on the app's Initialisms.
//
// Ranges a single key can state are checked when cfgx loads. Those that
// relate two keys (session.remembered_idle at least session.idle, and
// session.lifetime at least that) and the secret's length are checked by
// auth.New, which refuses a config outside every range of §4.8.
package authschema

import (
	"runtime"
	"time"

	"github.com/epistemer/cfgx/dsl"
)

// Group returns the cfgx group auth: its keys, defaults and ranges.
// members are nested in it, such as Passkey().
func Group(members ...dsl.Member) *dsl.GroupDef {
	h := time.Hour
	keys := []dsl.Member{
		dsl.String("issuer", "Issuer: the name in tokens and authenticator apps").Required(),
		dsl.Secret("secret", "Master secret, at least 32 bytes; every key is derived from it").Required(),
		dsl.Secret("secret_previous", "Previous master secret, while rotating"),
		dsl.Group("session", "Sessions",
			dsl.Duration("idle", "Idle lifetime of a session").Default(24*h).Min(5*time.Minute),
			dsl.Duration("remembered_idle", "Idle lifetime of a remembered session").Default(720*h).Min(5*time.Minute),
			dsl.Duration("lifetime", "Longest lifetime of a session, whatever its use").Default(2160*h).Min(5*time.Minute),
		),
		dsl.Group("access", "Access tokens",
			dsl.Duration("lifetime", "Lifetime of an access token").Default(10*time.Minute).Range(time.Minute, h),
		),
		dsl.Group("refresh", "Refresh tokens",
			dsl.Duration("grace", "How long a replaced refresh token still returns its successor").Default(10*time.Second).Range(0, time.Minute),
		),
		dsl.Group("flow", "Sign-in flows",
			dsl.Duration("lifetime", "Lifetime of a sign-in flow").Default(15*time.Minute).Range(time.Minute, h),
		),
		dsl.Group("fresh", "Fresh proofs",
			dsl.Duration("window", "How recent a proof must be to change a factor").Default(10*time.Minute).Range(time.Minute, h),
		),
		dsl.Group("code", "Codes sent by email or SMS",
			dsl.Int("length", "Digits in a code").Default(6).Range(6, 10),
			dsl.Duration("lifetime", "Lifetime of a code").Default(5*time.Minute).Range(time.Minute, 15*time.Minute),
			dsl.Int("tries", "Wrong tries a code allows").Default(5).Range(1, 10),
			dsl.Duration("resend", "Wait before another code may be sent").Default(time.Minute).Min(10*time.Second),
			dsl.Int("hourly", "Codes a user may be sent in an hour").Default(5).Range(1, 20),
		),
		dsl.Group("link", "Links sent by email",
			dsl.Duration("lifetime", "Lifetime of a recovery link").Default(30*time.Minute).Range(5*time.Minute, 24*h),
		),
		dsl.Group("invitation", "Invitations",
			dsl.Duration("lifetime", "Lifetime of an invitation").Default(72*h).Range(h, 720*h),
		),
		dsl.Group("device", "Registered devices",
			dsl.Duration("lifetime", "Lifetime of a registered device").Default(2160*h).Min(24*h),
		),
		dsl.Group("password", "Passwords",
			dsl.Int("min_length", "Fewest characters in a password").Default(12).Min(8),
			dsl.Int("min_score", "Least strength a new password needs, 3 or 4").Default(4).Range(3, 4),
			dsl.Int("memory", "Memory for each password hash, in MiB").Default(64).Range(19, 4096),
			dsl.Int("time", "Passes of each password hash").Default(2).Range(1, 64),
			dsl.Int("concurrency", "Password hashes at once").DefaultFunc(runtime.NumCPU).Min(1),
		),
		dsl.Group("throttle", "Throttling of wrong proofs",
			dsl.Int("free", "Failures before waits start").Default(5).Range(1, 20),
			dsl.Duration("ceiling", "Longest wait").Default(15*time.Minute).Range(time.Minute, 24*h),
			dsl.Duration("window", "Time without a failure after which a counter starts again").Default(h).Range(time.Minute, 24*h),
		),
		dsl.Group("cookie", "Cookies",
			dsl.Bool("insecure", "Drop Secure and the __Host- prefix, for development over plain HTTP"),
		),
		dsl.Strings("trusted_origins", "Origins whose cross-origin requests are trusted"),
	}
	return dsl.Group("auth", "Sign-in and sessions", append(keys, members...)...).GoName("Auth")
}

// Passkey returns the group passkey, for auth/passkey (interface §4.11):
// domain, the relying party ID, which an app with passkeys must set, and
// origins. passkey.New checks both; an app without passkeys leaves the
// group out, so it neither shows nor asks for them.
func Passkey() *dsl.GroupDef {
	return dsl.Group("passkey", "Passkeys",
		dsl.String("domain", "Domain passkeys are bound to: the site's, without scheme or port").Required(),
		dsl.Strings("origins", "Origins passkeys may be used from; https://<domain> when empty"),
	)
}
