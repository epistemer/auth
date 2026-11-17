package settings

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/epistemer/cfgx"
	"github.com/epistemer/cfgx/cfgxtest"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth"
)

// M1.6's done-when: a generated config satisfies auth.Config.
var _ auth.Config = (*Serve)(nil)

// With authschema.Passkey() nested, it satisfies passkey.Config too
// (interface §4.11), named here so authschema needn't import the module.
var _ interface {
	AuthIssuer() string
	AuthPasskeyDomain() string
	AuthPasskeyOrigins() []string
} = (*Serve)(nil)

// The passkey keys load from the environment, the origins as a list.
func TestPasskeyKeys(t *testing.T) {
	s, err := LoadServe(context.Background(), cfgx.WithEnv(map[string]string{
		"SHOP_AUTH_ISSUER":          "toyshop",
		"SHOP_AUTH_SECRET":          "0123456789abcdef0123456789abcdef",
		"SHOP_AUTH_PASSKEY_DOMAIN":  "toyshop.example",
		"SHOP_AUTH_PASSKEY_ORIGINS": "https://toyshop.example,https://shop.toyshop.example:8443",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if s.AuthPasskeyDomain() != "toyshop.example" || len(s.AuthPasskeyOrigins()) != 2 || s.AuthPasskeyOrigins()[1] != "https://shop.toyshop.example:8443" {
		t.Errorf("domain %q, origins %q", s.AuthPasskeyDomain(), s.AuthPasskeyOrigins())
	}
}

func TestGenerated(t *testing.T) { cfgxtest.AssertGenerated(t) }

// The defaults and ranges are interface §4.8's: loaded with only the
// required keys set, the config has the table's defaults, and auth.New's
// own check accepts it.
func TestDefaults(t *testing.T) {
	s, err := LoadServe(context.Background(), cfgx.WithEnv(map[string]string{
		"SHOP_AUTH_ISSUER":         "toyshop",
		"SHOP_AUTH_SECRET":         "0123456789abcdef0123456789abcdef",
		"SHOP_AUTH_PASSKEY_DOMAIN": "toyshop.example",
	}))
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ got, want any }{
		"session.idle":            {s.AuthSessionIdle(), 24 * time.Hour},
		"session.remembered_idle": {s.AuthSessionRememberedIdle(), 720 * time.Hour},
		"session.lifetime":        {s.AuthSessionLifetime(), 2160 * time.Hour},
		"access.lifetime":         {s.AuthAccessLifetime(), 10 * time.Minute},
		"refresh.grace":           {s.AuthRefreshGrace(), 10 * time.Second},
		"flow.lifetime":           {s.AuthFlowLifetime(), 15 * time.Minute},
		"fresh.window":            {s.AuthFreshWindow(), 10 * time.Minute},
		"code.length":             {s.AuthCodeLength(), 6},
		"code.lifetime":           {s.AuthCodeLifetime(), 5 * time.Minute},
		"code.tries":              {s.AuthCodeTries(), 5},
		"code.resend":             {s.AuthCodeResend(), time.Minute},
		"code.hourly":             {s.AuthCodeHourly(), 5},
		"link.lifetime":           {s.AuthLinkLifetime(), 30 * time.Minute},
		"invitation.lifetime":     {s.AuthInvitationLifetime(), 72 * time.Hour},
		"device.lifetime":         {s.AuthDeviceLifetime(), 2160 * time.Hour},
		"password.min_length":     {s.AuthPasswordMinLength(), 12},
		"password.min_score":      {s.AuthPasswordMinScore(), 4},
		"password.memory":         {s.AuthPasswordMemory(), 64},
		"password.time":           {s.AuthPasswordTime(), 2},
		"throttle.free":           {s.AuthThrottleFree(), 5},
		"throttle.ceiling":        {s.AuthThrottleCeiling(), 15 * time.Minute},
		"throttle.window":         {s.AuthThrottleWindow(), time.Hour},
		"cookie.insecure":         {s.AuthCookieInsecure(), false},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v; want %v", name, c.got, c.want)
		}
	}
	if s.AuthPasswordConcurrency() < 1 || len(s.AuthTrustedOrigins()) != 0 || s.AuthSecretPrevious().IsSet() {
		t.Error("concurrency, trusted_origins or secret_previous")
	}
	db, err := bolt.Open(filepath.Join(t.TempDir(), "shop.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := auth.New(db, s, nobody{}, nobody{}); err != nil {
		t.Errorf("auth.New refused the defaults: %v", err)
	}
}

type nobody struct{}

func (nobody) Find(context.Context, string) (auth.User, error) { return auth.User{}, auth.ErrNoUser }
func (nobody) Get(context.Context, auth.UserID) (auth.User, error) {
	return auth.User{}, auth.ErrNoUser
}
func (nobody) Address(context.Context, auth.UserID, auth.Channel) (string, error) {
	return "", nil
}
func (nobody) Send(context.Context, auth.Message) error { return nil }

// Values outside a key's range are refused when the config loads, on both
// sides; the edges are accepted. Ranges between keys and the secret's
// length are auth.New's (amendment A9).
func TestRanges(t *testing.T) {
	base := map[string]string{
		"SHOP_AUTH_ISSUER":         "toyshop",
		"SHOP_AUTH_SECRET":         "0123456789abcdef0123456789abcdef",
		"SHOP_AUTH_PASSKEY_DOMAIN": "toyshop.example",
	}
	load := func(env, v string) error {
		e := map[string]string{}
		for k, x := range base {
			e[k] = x
		}
		if env != "" {
			e[env] = v
		}
		_, err := LoadServe(context.Background(), cfgx.WithEnv(e))
		return err
	}
	for key, c := range map[string]struct{ lo, hi, below, above string }{
		"SESSION_IDLE":            {"5m", "", "4m", ""},
		"SESSION_REMEMBERED_IDLE": {"5m", "", "4m", ""},
		"SESSION_LIFETIME":        {"5m", "", "4m", ""},
		"ACCESS_LIFETIME":         {"1m", "1h", "59s", "61m"},
		"REFRESH_GRACE":           {"1s", "1m", "", "61s"},
		"FLOW_LIFETIME":           {"1m", "1h", "59s", "61m"},
		"FRESH_WINDOW":            {"1m", "1h", "59s", "61m"},
		"CODE_LENGTH":             {"6", "10", "5", "11"},
		"CODE_LIFETIME":           {"1m", "15m", "59s", "16m"},
		"CODE_TRIES":              {"1", "10", "", "11"},
		"CODE_RESEND":             {"10s", "", "9s", ""},
		"CODE_HOURLY":             {"1", "20", "", "21"},
		"LINK_LIFETIME":           {"5m", "24h", "4m", "25h"},
		"INVITATION_LIFETIME":     {"1h", "720h", "59m", "721h"},
		"DEVICE_LIFETIME":         {"24h", "", "23h", ""},
		"PASSWORD_MIN_LENGTH":     {"8", "", "7", ""},
		"PASSWORD_MIN_SCORE":      {"3", "4", "2", "5"},
		"PASSWORD_MEMORY":         {"19", "4096", "18", "4097"},
		"PASSWORD_TIME":           {"1", "64", "", "65"},
		"PASSWORD_CONCURRENCY":    {"1", "", "-1", ""},
		"THROTTLE_FREE":           {"1", "20", "", "21"},
		"THROTTLE_CEILING":        {"1m", "24h", "59s", "25h"},
		"THROTTLE_WINDOW":         {"1m", "24h", "59s", "25h"},
	} {
		env := "SHOP_AUTH_" + key
		for _, v := range []string{c.lo, c.hi} {
			if v != "" {
				if err := load(env, v); err != nil {
					t.Errorf("%s=%s: %v", env, v, err)
				}
			}
		}
		for _, v := range []string{c.below, c.above} {
			if v != "" && load(env, v) == nil {
				t.Errorf("%s=%s was accepted", env, v)
			}
		}
	}
	for _, missing := range []string{"SHOP_AUTH_ISSUER", "SHOP_AUTH_SECRET", "SHOP_AUTH_PASSKEY_DOMAIN"} {
		e := map[string]string{}
		for k, x := range base {
			if k != missing {
				e[k] = x
			}
		}
		if _, err := LoadServe(context.Background(), cfgx.WithEnv(e)); err == nil {
			t.Errorf("a config without %s was accepted", missing)
		}
	}
}
