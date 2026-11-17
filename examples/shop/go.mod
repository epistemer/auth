module github.com/epistemer/auth/examples/shop

go 1.26.0

replace (
	github.com/epistemer/auth => ../..
	github.com/epistemer/auth/authschema => ../../authschema
	github.com/epistemer/auth/passkey => ../../passkey
)

tool github.com/epistemer/cfgx/cmd/cfgx

require (
	github.com/epistemer/auth v0.1.0
	github.com/epistemer/auth/authschema v0.0.0-20261116012024-e2d8b21fccda
	github.com/epistemer/auth/passkey v0.0.0
	github.com/epistemer/cfgx v0.2.0
	github.com/epistemer/errors v0.1.0
	github.com/spf13/cobra v1.10.2
	go.etcd.io/bbolt v1.5.0
)

require (
	github.com/epistemer/i18n v0.3.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.4 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/webauthn v0.18.2 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.yaml.in/yaml/v4 v4.0.0 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
