package auth

import (
	"github.com/epistemer/auth/internal/password"
	"github.com/epistemer/auth/internal/testhook"
)

// cheapParams are below what a config may ask for (interface §4.8): for
// authtest only, through testhook.
var cheapParams = password.Params{MemoryKiB: 64, Time: 1}

func init() {
	testhook.CheapHashing = Option(func(a *Auth) {
		h, err := password.New(cheapParams, 4)
		if err != nil {
			panic(err)
		}
		a.hasher = h
	})
}
