// Package testhook lets authtest reach what auth keeps unexported. Only
// packages in auth's module can import it.
package testhook

// CheapHashing is an auth.Option, as any, that swaps in password hashing
// cheap enough for tests. auth sets it at init.
var CheapHashing any
