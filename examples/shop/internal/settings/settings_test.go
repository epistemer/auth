package settings

import (
	"testing"

	"github.com/epistemer/cfgx/cfgxtest"

	"github.com/epistemer/auth"
	"github.com/epistemer/auth/oidc"
	"github.com/epistemer/auth/passkey"
)

// The settings cfgx generated satisfy auth.Config and passkey.Config.
var (
	_ auth.Config    = (*Serve)(nil)
	_ passkey.Config = (*Serve)(nil)
	_ oidc.Config    = (*Serve)(nil)
)

func TestGenerated(t *testing.T) { cfgxtest.AssertGenerated(t) }
