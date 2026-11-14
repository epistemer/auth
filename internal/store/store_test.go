package store_test

import (
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/epistemer/auth/internal/secrets"
	"github.com/epistemer/auth/internal/store"
	pb "github.com/epistemer/auth/internal/storepb"
	"github.com/google/go-cmp/cmp"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func open(t *testing.T) *bolt.DB {
	t.Helper()
	db, err := bolt.Open(filepath.Join(t.TempDir(), "auth.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Init(db); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestInitIsIdempotent(t *testing.T) {
	db := open(t)
	if err := store.Init(db); err != nil {
		t.Fatalf("second Init: %v", err)
	}
}

func TestInitRefusesNewerLayout(t *testing.T) {
	db := open(t)
	db.Update(func(tx *bolt.Tx) error {
		return store.B(tx, store.Meta).Put([]byte("version"), []byte{store.Version + 1})
	})
	if err := store.Init(db); !errors.Is(err, store.ErrVersion) {
		t.Fatalf("got %v", err)
	}
}

func TestEveryRecordRoundTrips(t *testing.T) {
	addr, _ := netip.MustParseAddr("2001:db8::1").MarshalBinary()
	_, tokHash := secrets.NewToken()
	records := []struct {
		bucket []byte
		key    []byte
		msg    proto.Message
		empty  proto.Message
	}{
		{store.Sessions, []byte("s1"), &pb.Session{
			Id: "s1", UserId: "u1", TokenHash: tokHash, Carrier: pb.Carrier_CARRIER_BEARER,
			Verified: true, Generation: 3,
			Factors:  []*pb.Factor{{Method: "password", At: 1}, {Method: "email_code", At: 2, Channel: []byte{9}}},
			DeviceId: "d1", Remembered: true, Created: 1, Seen: 2, Expires: 3,
			Client: &pb.Client{Addr: addr, UserAgent: "test"}, Claims: []byte(`{"balance":"10.00"}`),
		}, &pb.Session{}},
		{store.Refresh, tokHash, &pb.Refresh{SessionId: "s1", Issued: 1, Replaced: 2, Successor: []byte{1, 2}}, &pb.Refresh{}},
		{store.Flows, tokHash, &pb.Flow{
			Purpose: 1, UserId: "u1", LoginKey: []byte("alice"), SessionId: "s1",
			Carrier: pb.Carrier_CARRIER_COOKIE, Created: 1, Expires: 2,
			Proofs: []*pb.Factor{{Method: "password", At: 1}}, DeviceId: "d1",
			Codes:    []*pb.CodeState{{Method: "email_code", Mac: []byte{1}, Sent: 1, Expires: 2, Tries: 3, Burnt: true}},
			LinkHash: tokHash, EnrollMethod: "totp", Pending: []byte{7},
			MethodState: map[string][]byte{"passkey": {1}, "oidc:x": {2}}, NoUser: true,
		}, &pb.Flow{}},
		{store.Credentials, store.Key([]byte("u1"), []byte("password"), store.CredKey(nil)), &pb.Credential{
			Method: "password", Data: []byte("$argon2id$v=19$m=65536,t=2,p=1$c2FsdA$aGFzaA"), Added: 1, Used: 2,
		}, &pb.Credential{}},
		{store.Devices, []byte("d1"), &pb.Device{Id: "d1", UserId: "u1", TokenHash: tokHash, Label: "laptop", Created: 1, Used: 2, Expires: 3}, &pb.Device{}},
		{store.Links, tokHash, &pb.Link{Purpose: 3, UserId: "u1", FlowHash: tokHash, Created: 1, Expires: 2, Spent: 3}, &pb.Link{}},
		{store.Throttle, store.Key([]byte("u"), []byte("u1")), &pb.Counter{Failures: 6, Last: 1, Until: 2}, &pb.Counter{}},
	}
	db := open(t)
	err := db.Update(func(tx *bolt.Tx) error {
		for _, r := range records {
			if err := store.Put(tx, r.bucket, r.key, r.msg); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	db.View(func(tx *bolt.Tx) error {
		for _, r := range records {
			got := r.empty
			if err := store.Get(tx, r.bucket, r.key, got); err != nil {
				t.Errorf("%s: %v", r.bucket, err)
				continue
			}
			if d := cmp.Diff(r.msg, got, protocmp.Transform()); d != "" {
				t.Errorf("%s (-want +got):\n%s", r.bucket, d)
			}
		}
		if err := store.Get(tx, store.Sessions, []byte("missing"), &pb.Session{}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("missing: %v", err)
		}
		return nil
	})
}

func TestBuiltInCredentialData(t *testing.T) {
	for _, m := range []proto.Message{
		&pb.TOTPData{SealedSecret: []byte{1, 2, 3}, LastStep: 59000000},
		&pb.RecoveryData{Hashes: [][]byte{{1}, {2}}, Used: []bool{false, true}},
	} {
		b, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		got := m.ProtoReflect().New().Interface()
		if err := proto.Unmarshal(b, got); err != nil {
			t.Fatal(err)
		}
		if d := cmp.Diff(m, got, protocmp.Transform()); d != "" {
			t.Errorf("%T:\n%s", m, d)
		}
	}
}

// M1.1's done-when: a record sealed and MACed under one secret still opens
// and verifies after the secret is rotated, through the store.
func TestPreviousSecretThroughTheStore(t *testing.T) {
	a := []byte(strings.Repeat("a", 32))
	b := []byte(strings.Repeat("b", 32))
	before, _ := secrets.New(a, nil)
	sealed, err := before.Seal([]byte("JBSWY3DPEHPK3PXP"), []byte("u1"))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := proto.Marshal(&pb.TOTPData{SealedSecret: sealed})
	mac := before.MAC(secrets.Codes, []byte("flow"), []byte("123456"))

	db := open(t)
	key := store.Key([]byte("u1"), []byte("totp"), store.CredKey([]byte("k")))
	db.Update(func(tx *bolt.Tx) error {
		if err := store.Put(tx, store.Credentials, key, &pb.Credential{Method: "totp", Data: data}); err != nil {
			return err
		}
		return store.Put(tx, store.Flows, []byte("f"), &pb.Flow{Codes: []*pb.CodeState{{Mac: mac}}})
	})

	after, _ := secrets.New(b, a)
	db.View(func(tx *bolt.Tx) error {
		var c pb.Credential
		var d pb.TOTPData
		var f pb.Flow
		if err := store.Get(tx, store.Credentials, key, &c); err != nil {
			t.Fatal(err)
		}
		if err := proto.Unmarshal(c.Data, &d); err != nil {
			t.Fatal(err)
		}
		pt, stale, err := after.Open(d.SealedSecret, []byte("u1"))
		if err != nil || !stale || string(pt) != "JBSWY3DPEHPK3PXP" {
			t.Fatalf("open after rotation: %q %v %v", pt, stale, err)
		}
		if err := store.Get(tx, store.Flows, []byte("f"), &f); err != nil || len(f.Codes) != 1 {
			t.Fatalf("flow: %v", err)
		}
		if !after.Verify(secrets.Codes, f.Codes[0].Mac, []byte("flow"), []byte("123456")) {
			t.Fatal("code MAC doesn't verify after rotation")
		}
		return nil
	})
}

// A record read in one transaction must stay intact after the transaction
// ends and later writes reuse bbolt's pages.
func TestRecordsOutliveTheirTransaction(t *testing.T) {
	db := open(t)
	want := []byte(strings.Repeat("x", 4096))
	db.Update(func(tx *bolt.Tx) error {
		return store.Put(tx, store.Sessions, []byte("s"), &pb.Session{Claims: want, TokenHash: want[:32]})
	})
	var got pb.Session
	db.View(func(tx *bolt.Tx) error { return store.Get(tx, store.Sessions, []byte("s"), &got) })
	for i := range 200 {
		db.Update(func(tx *bolt.Tx) error {
			if err := store.Delete(tx, store.Sessions, []byte("s")); err != nil {
				return err
			}
			return store.Put(tx, store.Sessions, []byte(strings.Repeat("k", i%50+1)), &pb.Session{Claims: []byte(strings.Repeat("y", 4096))})
		})
	}
	if string(got.Claims) != string(want) || string(got.TokenHash) != string(want[:32]) {
		t.Fatal("a record changed after its transaction ended")
	}
}

func TestCredKeyAllowsAnyBytes(t *testing.T) {
	id := []byte{0x00, 0x01, 0x00, 0xff}
	k := store.Key([]byte("u1"), []byte("passkey"), store.CredKey(id))
	if len(k) != len("u1")+1+len("passkey")+1+32 {
		t.Fatalf("key %x", k)
	}
	if string(store.CredKey(id)) == string(store.CredKey(id[:3])) {
		t.Fatal("two credential keys share a hash")
	}
}

func TestKey(t *testing.T) {
	if store.Key() != nil {
		t.Fatal("Key() isn't nil")
	}
	if got := string(store.Key([]byte("u1"), []byte("totp"), []byte("k"))); got != "u1\x00totp\x00k" {
		t.Fatalf("%q", got)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a zero byte in a part didn't panic")
		}
	}()
	store.Key([]byte("u1\x00x"), []byte("y"))
}

func TestScanStaysInPrefix(t *testing.T) {
	db := open(t)
	db.Update(func(tx *bolt.Tx) error {
		for _, k := range []string{"u1\x00a", "u1\x00b", "u10\x00c", "u2\x00d"} {
			store.B(tx, store.SessionsByUser).Put([]byte(k), nil)
		}
		return nil
	})
	var got []string
	db.View(func(tx *bolt.Tx) error {
		return store.Scan(tx, store.SessionsByUser, store.Prefix([]byte("u1")), func(k, _ []byte) error {
			got = append(got, string(k))
			return nil
		})
	})
	if d := cmp.Diff([]string{"u1\x00a", "u1\x00b"}, got); d != "" {
		t.Fatalf("u1's sessions (-want +got):\n%s", d)
	}
}
