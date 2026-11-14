module github.com/epistemer/auth

go 1.26.0

require (
	github.com/google/go-cmp v0.7.0
	go.etcd.io/bbolt v1.5.0
	google.golang.org/protobuf v1.36.12
)

require golang.org/x/sys v0.45.0 // indirect

tool google.golang.org/protobuf/cmd/protoc-gen-go
