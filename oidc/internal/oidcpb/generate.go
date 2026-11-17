// Package oidcpb holds the protobuf records auth/oidc keeps.
//
// The file is oidc_records.proto: protobuf registers every file by its
// path in one process-wide registry, so its name is unique to this module.
package oidcpb

// Regenerate with protoc 3.21.x and the protoc-gen-go version pinned in
// the core's go.mod (ADR 0005).
//go:generate sh -c "protoc --plugin=protoc-gen-go=\"$(cd ../../.. && go tool -n protoc-gen-go)\" --go_out=. --go_opt=paths=source_relative oidc_records.proto"
