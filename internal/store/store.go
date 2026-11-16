// Package store lays out auth's records in bbolt (interface §8, ADR 0005).
//
// Everything lives under one top-level bucket, "auth". The layout is
// private: apps read through the API.
package store

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

// Root is the top-level bucket.
var Root = []byte("auth")

// Buckets under Root. The names are permanent.
var (
	Sessions       = []byte("sessions")         // <id> -> Session
	SessionTokens  = []byte("session_tokens")   // sha256(token) -> id
	SessionsByUser = []byte("sessions_by_user") // <user>\x00<id> -> empty
	Refresh        = []byte("refresh")          // sha256(token) -> Refresh
	// <session>\x00hex(sha256(token)) -> empty: a session's refresh tokens
	RefreshBySession = []byte("refresh_by_session")
	Flows            = []byte("flows")           // sha256(token) -> Flow
	Credentials      = []byte("credentials")     // <user>\x00<method>\x00sha256(<key>) -> Credential
	CredentialKeys   = []byte("credential_keys") // <method>\x00sha256(<key>) -> <user>
	Devices          = []byte("devices")         // <id> -> Device
	DeviceTokens     = []byte("device_tokens")   // sha256(token) -> id
	DevicesByUser    = []byte("devices_by_user") // <user>\x00<id> -> empty
	Links            = []byte("links")           // sha256(token) -> Link
	Throttle         = []byte("throttle")        // <kind>\x00<key> -> Counter
	Meta             = []byte("meta")            // "version" -> layout version
)

var all = [][]byte{
	Sessions, SessionTokens, SessionsByUser, Refresh, RefreshBySession, Flows, Credentials,
	CredentialKeys, Devices, DeviceTokens, DevicesByUser, Links, Throttle, Meta,
}

// Version is the layout this code writes and reads.
const Version = 1

var versionKey = []byte("version")

// ErrNotFound is returned by Get for a missing record.
var ErrNotFound = errors.New("store: not found")

// ErrVersion is returned by Init for a store written by a newer layout.
var ErrVersion = errors.New("store: written by a newer version of auth")

// Init creates the buckets and records the layout version. It refuses a
// store a newer layout wrote.
func Init(db *bolt.DB) error {
	return db.Update(func(tx *bolt.Tx) error {
		root, err := tx.CreateBucketIfNotExists(Root)
		if err != nil {
			return err
		}
		for _, name := range all {
			if _, err := root.CreateBucketIfNotExists(name); err != nil {
				return fmt.Errorf("store: bucket %s: %w", name, err)
			}
		}
		meta := root.Bucket(Meta)
		if v := meta.Get(versionKey); v != nil {
			if len(v) != 1 || v[0] > Version {
				return ErrVersion
			}
			return nil
		}
		return meta.Put(versionKey, []byte{Version})
	})
}

// B returns a bucket under Root. Init must have run.
func B(tx *bolt.Tx, name []byte) *bolt.Bucket {
	return tx.Bucket(Root).Bucket(name)
}

// Get decodes the record at key into m. protobuf copies every field out of
// the input, so m stays valid after tx ends although bbolt's value doesn't.
func Get(tx *bolt.Tx, bucket, key []byte, m proto.Message) error {
	v := B(tx, bucket).Get(key)
	if v == nil {
		return ErrNotFound
	}
	return proto.Unmarshal(v, m)
}

// Put encodes m at key. Encoding is deterministic, so equal records are
// equal bytes.
func Put(tx *bolt.Tx, bucket, key []byte, m proto.Message) error {
	v, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return err
	}
	return B(tx, bucket).Put(key, v)
}

// Delete removes key. A missing key is not an error.
func Delete(tx *bolt.Tx, bucket, key []byte) error {
	return B(tx, bucket).Delete(key)
}

// Key joins parts with a zero byte. A part must not contain one: IDs,
// method names and hashes as keys never do, and Key panics otherwise, since
// it would let one key pose as another.
func Key(parts ...[]byte) []byte {
	if len(parts) == 0 {
		return nil
	}
	n := len(parts) - 1
	for _, p := range parts {
		n += len(p)
	}
	k := make([]byte, 0, n)
	for i, p := range parts {
		if bytes.IndexByte(p, 0) >= 0 {
			panic("store: a key part contains a zero byte")
		}
		if i > 0 {
			k = append(k, 0)
		}
		k = append(k, p...)
	}
	return k
}

// CredKey is how a method's credential key appears in a store key: its
// SHA-256. A method's keys are arbitrary bytes (a passkey's ID can hold a
// zero byte) and of any length; the hash is neither.
func CredKey(key []byte) []byte {
	s := sha256.Sum256(key)
	return s[:]
}

// Prefix is Key with a trailing separator, for scanning every record under
// the first parts.
func Prefix(parts ...[]byte) []byte {
	return append(Key(parts...), 0)
}

// Scan calls f for each key under prefix in bucket, in key order. f must not
// change the bucket; collect keys and delete after. f gets copies, so it may
// keep them; bbolt's own slices go stale once the bucket changes.
func Scan(tx *bolt.Tx, bucket, prefix []byte, f func(k, v []byte) error) error {
	c := B(tx, bucket).Cursor()
	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		if err := f(bytes.Clone(k), bytes.Clone(v)); err != nil {
			return err
		}
	}
	return nil
}
