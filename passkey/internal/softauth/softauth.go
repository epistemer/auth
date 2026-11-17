// Package softauth is a software WebAuthn authenticator for tests. It
// answers creation and request options with real attestations ("none") and
// signed assertions, and can be told to misbehave: drop a flag, replay a
// counter, answer for another origin or relying party, and so on.
// passkeytest wraps it with no knobs for apps.
package softauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

var b64 = base64.RawURLEncoding

// COSE algorithms it can hold a key for.
const (
	ES256 = -7
	EdDSA = -8
	ES384 = -35
	RS256 = -257
)

// Authenticator holds at most one credential. Its exported fields are
// knobs, read at each Create or Get.
type Authenticator struct {
	Origin string
	Alg    int64 // ES256 unless set

	ID         []byte // the credential ID; random at Create unless set
	UserHandle []byte // set by Create from the options; a Get sends it
	Counter    uint32
	Step       uint32 // added to Counter at each Get; 1 unless NoStep
	NoStep     bool   // the counter doesn't move (a synced passkey: zero)

	NoUP, NoUV  bool
	BE, BS      bool // backup-eligible and backup state flags
	CrossOrigin bool
	TopOrigin   string
	Type        string // the client data's type, when set
	RPID        string // the relying party ID it signs for, when set
	NoHandle    bool   // a Get sends no user handle
	Handle      []byte // a Get sends this user handle, when set
	Challenge   string // the client data's challenge, when set
	Transports  []string
	Format      string // "packed": a self-attestation with a bad signature; "self": a good one
	COSE        []byte // the public key Create reports, when set
	AT          bool   // a Get sets the attested-data flag
	AttestedID  []byte // the credential ID inside the attestation, when set
	BadSig      bool   // a Get's signature is corrupted

	key crypto.Signer
}

// New returns an authenticator answering as origin, with no credential.
func New(origin string) *Authenticator { return &Authenticator{Origin: origin, Alg: ES256} }

type options struct {
	RP struct {
		ID string `json:"id"`
	} `json:"rp"`
	RPID string `json:"rpId"`
	User struct {
		ID string `json:"id"`
	} `json:"user"`
	Challenge string `json:"challenge"`
}

func (a *Authenticator) newKey() (cose []byte, err error) {
	switch a.Alg {
	case ES256, ES384:
		curve, crv, size := elliptic.P256(), 1, 32
		if a.Alg == ES384 {
			curve, crv, size = elliptic.P384(), 2, 48
		}
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		a.key = k
		x, y := make([]byte, size), make([]byte, size)
		k.X.FillBytes(x)
		k.Y.FillBytes(y)
		return webauthncbor.Marshal(map[int]any{1: 2, 3: a.Alg, -1: crv, -2: x, -3: y})
	case EdDSA:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		a.key = priv
		return webauthncbor.Marshal(map[int]any{1: 1, 3: EdDSA, -1: 6, -2: []byte(pub)})
	case RS256:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		a.key = k
		return webauthncbor.Marshal(map[int]any{1: 3, 3: RS256, -1: k.N.Bytes(), -2: big.NewInt(int64(k.E)).Bytes()})
	}
	return nil, errors.New("softauth: no such algorithm")
}

func (a *Authenticator) sign(data []byte) ([]byte, error) {
	switch k := a.key.(type) {
	case *ecdsa.PrivateKey:
		var h []byte
		if a.Alg == ES384 {
			s := sha512.Sum384(data)
			h = s[:]
		} else {
			s := sha256.Sum256(data)
			h = s[:]
		}
		return ecdsa.SignASN1(rand.Reader, k, h)
	case ed25519.PrivateKey:
		return ed25519.Sign(k, data), nil
	case *rsa.PrivateKey:
		h := sha256.Sum256(data)
		return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	}
	return nil, errors.New("softauth: no key")
}

func (a *Authenticator) flags(at bool) byte {
	var f byte
	if !a.NoUP {
		f |= 0x01
	}
	if !a.NoUV {
		f |= 0x04
	}
	if a.BE {
		f |= 0x08
	}
	if a.BS {
		f |= 0x10
	}
	if at {
		f |= 0x40
	}
	return f
}

func (a *Authenticator) authData(rpID string, at bool, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append(h[:], a.flags(at))
	out = binary.BigEndian.AppendUint32(out, a.Counter)
	return append(out, attested...)
}

func (a *Authenticator) clientData(typ, challenge string) []byte {
	if a.Type != "" {
		typ = a.Type
	}
	if a.Challenge != "" {
		challenge = a.Challenge
	}
	cd := map[string]any{"type": typ, "challenge": challenge, "origin": a.Origin}
	if a.CrossOrigin {
		cd["crossOrigin"] = true
	}
	if a.TopOrigin != "" {
		cd["topOrigin"] = a.TopOrigin
	}
	j, _ := json.Marshal(cd)
	return j
}

// Create answers creation options with a new credential, and returns the
// JSON a browser's PublicKeyCredential.toJSON() gives.
func (a *Authenticator) Create(opts json.RawMessage) ([]byte, error) {
	var o options
	if err := json.Unmarshal(opts, &o); err != nil {
		return nil, err
	}
	handle, err := b64.DecodeString(o.User.ID)
	if err != nil {
		return nil, err
	}
	a.UserHandle = handle
	cose, err := a.newKey()
	if err != nil {
		return nil, err
	}
	if a.ID == nil {
		a.ID = make([]byte, 16)
		rand.Read(a.ID)
	}
	rpID := o.RP.ID
	if a.RPID != "" {
		rpID = a.RPID
	}
	if a.COSE != nil {
		cose = a.COSE
	}
	inner := a.ID
	if a.AttestedID != nil {
		inner = a.AttestedID
	}
	attested := make([]byte, 16) // AAGUID: zero
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(inner)))
	attested = append(append(attested, inner...), cose...)
	authData := a.authData(rpID, true, attested)
	format, stmt := "none", map[string]any{}
	switch a.Format {
	case "packed":
		format, stmt = "packed", map[string]any{"alg": a.Alg, "sig": []byte{1, 2, 3}}
	case "self":
		h := sha256.Sum256(a.clientData("webauthn.create", o.Challenge))
		sig, err := a.sign(append(append([]byte{}, authData...), h[:]...))
		if err != nil {
			return nil, err
		}
		format, stmt = "packed", map[string]any{"alg": a.Alg, "sig": sig}
	}
	obj, err := webauthncbor.Marshal(map[string]any{"fmt": format, "attStmt": stmt, "authData": authData})
	if err != nil {
		return nil, err
	}
	ts := a.Transports
	if ts == nil {
		ts = []string{"internal", "hybrid"}
	}
	return json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.ID), "rawId": b64.EncodeToString(a.ID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(a.clientData("webauthn.create", o.Challenge)),
			"attestationObject": b64.EncodeToString(obj),
			"transports":        ts,
		},
		"clientExtensionResults":  map[string]any{},
		"authenticatorAttachment": "platform",
	})
}

// Get answers request options with an assertion by the credential.
func (a *Authenticator) Get(opts json.RawMessage) ([]byte, error) {
	if a.key == nil {
		return nil, errors.New("softauth: no credential")
	}
	var o options
	if err := json.Unmarshal(opts, &o); err != nil {
		return nil, err
	}
	if !a.NoStep {
		step := a.Step
		if step == 0 {
			step = 1
		}
		a.Counter += step
	}
	rpID := o.RPID
	if a.RPID != "" {
		rpID = a.RPID
	}
	authData := a.authData(rpID, a.AT, nil)
	cd := a.clientData("webauthn.get", o.Challenge)
	h := sha256.Sum256(cd)
	sig, err := a.sign(append(append([]byte{}, authData...), h[:]...))
	if err != nil {
		return nil, err
	}
	if a.BadSig {
		sig[len(sig)-1] ^= 1
	}
	resp := map[string]any{
		"clientDataJSON":    b64.EncodeToString(cd),
		"authenticatorData": b64.EncodeToString(authData),
		"signature":         b64.EncodeToString(sig),
	}
	switch {
	case a.Handle != nil:
		resp["userHandle"] = b64.EncodeToString(a.Handle)
	case !a.NoHandle:
		resp["userHandle"] = b64.EncodeToString(a.UserHandle)
	}
	return json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.ID), "rawId": b64.EncodeToString(a.ID), "type": "public-key",
		"response":               resp,
		"clientExtensionResults": map[string]any{},
	})
}
