package settings

import (
	"testing"

	"github.com/epistemer/cfgx/cfgxtest"

	"github.com/epistemer/auth"
)

// The settings cfgx generated satisfy auth.Config.
var _ auth.Config = (*Serve)(nil)

func TestGenerated(t *testing.T) { cfgxtest.AssertGenerated(t) }
