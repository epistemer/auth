// Package passkeypb holds the protobuf records auth/passkey keeps.
//
// The file is passkey_records.proto: protobuf registers every file by its
// path in one process-wide registry, so its name is unique to this module.
package passkeypb

// Regenerate with protoc 3.21.x and the protoc-gen-go version pinned in
// the core's go.mod (ADR 0005).
//go:generate sh -c "protoc --plugin=protoc-gen-go=\"$(cd ../../.. && go tool -n protoc-gen-go)\" --go_out=. --go_opt=paths=source_relative passkey_records.proto"
