// Package storepb holds the protobuf records auth stores in bbolt.
package storepb

// Regenerate with protoc 3.21.x and the protoc-gen-go version pinned in
// go.mod. See docs/adr/0005-store-layout.md.
//go:generate sh -c "protoc --plugin=protoc-gen-go=\"$(go tool -n protoc-gen-go)\" --go_out=. --go_opt=paths=source_relative records.proto"
