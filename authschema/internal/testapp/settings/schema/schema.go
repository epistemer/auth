// Package schema is a toy shop's configuration, to check that what cfgx
// generates from authschema's group satisfies auth.Config.
package schema

import (
	"github.com/epistemer/cfgx/dsl"

	"github.com/epistemer/auth/authschema"
)

// Auth is auth's own fragment, with passkeys.
var Auth = authschema.Group(authschema.Passkey())

// App is the toy shop.
var App = dsl.App("shop", "A toy shop", Auth)

// Serve runs the shop.
var Serve = dsl.Command("Serve").Uses(Auth)
