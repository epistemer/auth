// Package storepb holds the protobuf records auth stores in bbolt.
//
// The file is auth_records.proto, not records.proto: protobuf registers
// every file by its path in one process-wide registry, and i18n's records
// are records.proto too, so an app with both panicked at start.
package storepb

// Regenerate with protoc 3.21.x and the protoc-gen-go version pinned in
// go.mod. See docs/adr/0005-store-layout.md.
//go:generate sh -c "protoc --plugin=protoc-gen-go=\"$(go tool -n protoc-gen-go)\" --go_out=. --go_opt=paths=source_relative auth_records.proto"
