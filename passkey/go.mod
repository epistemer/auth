module github.com/epistemer/auth/passkey

go 1.26.0

require (
	github.com/epistemer/auth v0.2.0
	github.com/go-webauthn/webauthn v0.18.2
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/epistemer/cfgx v0.2.0 // indirect
	github.com/epistemer/errors v0.1.0 // indirect
	github.com/epistemer/i18n v0.3.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.4 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.etcd.io/bbolt v1.5.0 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
)

// Until the core's v0.3.0 is tagged (ADR 0004), the module builds against
// the core beside it.
replace github.com/epistemer/auth => ../
