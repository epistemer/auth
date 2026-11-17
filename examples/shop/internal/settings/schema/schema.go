// Package schema is the toy shop's configuration: auth's fragment, the
// listen address and the store file.
package schema

import (
	"github.com/epistemer/cfgx/dsl"

	"github.com/epistemer/auth/authschema"
)

// Auth is auth's own fragment, with passkeys and one provider: every app
// declares its keys the same way.
var Auth = authschema.Group(authschema.Passkey(), authschema.OIDC())

// Server is the HTTP listener and the store.
var Server = dsl.Group("server", "Web server",
	dsl.String("addr", "Listen address").Default("localhost:8080"),
	dsl.Path("store", "Store file").Default("shop.db"),
)

// App is the toy shop.
var App = dsl.App("shop", "A toy shop that signs people in", Auth, Server)

// Serve runs the shop.
var Serve = dsl.Command("Serve").Uses(Auth, Server)
