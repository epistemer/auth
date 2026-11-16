package auth

import (
	"bytes"
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/secrets"
	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// Registered devices (interface §5.7). A device is a token the server
// issued: whoever presents it, for the user it was issued to, may stand for
// the second proof when the policy trusts devices.

// DeviceInfo is a registered device, as a user's device list shows it.
type DeviceInfo struct {
	ID      DeviceID
	Label   string
	Created time.Time
	Used    time.Time
	Expires time.Time
}

type deviceTokenKey struct{}

// deviceFromCookie returns the device token Load read from the cookie.
func deviceFromCookie(ctx context.Context) string {
	t, _ := ctx.Value(deviceTokenKey{}).(string)
	return t
}

// findDevice returns the live device a token names for user, or nil: an
// unknown, expired or someone else's token is none, and says nothing more
// (§5.7.6). It reads even for an unknown login, so both cost the same.
func (a *Auth) findDevice(tx *bolt.Tx, token string, user UserID) (*storepb.Device, error) {
	if token == "" {
		return nil, nil
	}
	id := store.B(tx, store.DeviceTokens).Get(secrets.Hash(token))
	if id == nil {
		return nil, nil
	}
	d := new(storepb.Device)
	if err := store.Get(tx, store.Devices, id, d); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if user == "" || d.UserId != string(user) || a.now().UnixNano() >= d.Expires {
		return nil, nil
	}
	return d, nil
}

// liveDevice returns a user's device by ID if it is still registered and
// unexpired, or nil.
func (a *Auth) liveDevice(tx *bolt.Tx, id string, user UserID) (*storepb.Device, error) {
	if id == "" {
		return nil, nil
	}
	d := new(storepb.Device)
	if err := store.Get(tx, store.Devices, []byte(id), d); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if d.UserId != string(user) || a.now().UnixNano() >= d.Expires {
		return nil, nil
	}
	return d, nil
}

// flowDevice returns the device a flow presented if it is still a live
// device of the flow's user with the very token presented: a token replaced
// since, by another Finish, is none.
func (a *Auth) flowDevice(tx *bolt.Tx, rec *storepb.Flow) (*storepb.Device, error) {
	d, err := a.liveDevice(tx, rec.DeviceId, UserID(rec.UserId))
	if d == nil || err != nil || !bytes.Equal(d.TokenHash, rec.DeviceToken) {
		return nil, err
	}
	return d, nil
}

// deviceOK reports whether a flow's device is still good, in a read of its
// own.
func (a *Auth) deviceOK(rec *storepb.Flow) (bool, error) {
	if rec.DeviceId == "" {
		return false, nil
	}
	var ok bool
	err := a.db.View(func(tx *bolt.Tx) error {
		d, err := a.flowDevice(tx, rec)
		ok = d != nil
		return err
	})
	return ok, err
}

// registerDevice makes a device for user, in tx, and returns its token.
func (a *Auth) registerDevice(tx *bolt.Tx, user UserID, label string) (string, *storepb.Device, error) {
	now := a.now()
	token, hash := secrets.NewToken()
	d := &storepb.Device{
		Id: secrets.NewID(), UserId: string(user), TokenHash: hash, Label: label,
		Created: now.UnixNano(), Used: now.UnixNano(), Expires: now.Add(a.cfg.AuthDeviceLifetime()).UnixNano(),
	}
	if err := putDevice(tx, d); err != nil {
		return "", nil, err
	}
	return token, d, nil
}

// rotateDevice gives a device a new token, in tx, as the Finish of a
// sign-in that used it does (§5.7.5). Its lifetime starts again.
func (a *Auth) rotateDevice(tx *bolt.Tx, d *storepb.Device) (string, error) {
	if err := store.Delete(tx, store.DeviceTokens, d.TokenHash); err != nil {
		return "", err
	}
	now := a.now()
	token, hash := secrets.NewToken()
	d.TokenHash, d.Used, d.Expires = hash, now.UnixNano(), now.Add(a.cfg.AuthDeviceLifetime()).UnixNano()
	return token, putDevice(tx, d)
}

func putDevice(tx *bolt.Tx, d *storepb.Device) error {
	if err := store.Put(tx, store.Devices, []byte(d.Id), d); err != nil {
		return err
	}
	if err := store.B(tx, store.DeviceTokens).Put(d.TokenHash, []byte(d.Id)); err != nil {
		return err
	}
	return store.B(tx, store.DevicesByUser).Put(store.Key([]byte(d.UserId), []byte(d.Id)), nil)
}

// deleteDevice removes a device and its indexes, in tx.
func deleteDevice(tx *bolt.Tx, d *storepb.Device) error {
	if string(store.B(tx, store.DeviceTokens).Get(d.TokenHash)) == d.Id {
		if err := store.Delete(tx, store.DeviceTokens, d.TokenHash); err != nil {
			return err
		}
	}
	if err := store.Delete(tx, store.DevicesByUser, store.Key([]byte(d.UserId), []byte(d.Id))); err != nil {
		return err
	}
	return store.Delete(tx, store.Devices, []byte(d.Id))
}

// userDevices returns a user's device records, in tx.
func userDevices(tx *bolt.Tx, user UserID) ([]*storepb.Device, error) {
	var out []*storepb.Device
	err := store.Scan(tx, store.DevicesByUser, store.Prefix([]byte(user)), func(k, _ []byte) error {
		d := new(storepb.Device)
		if err := store.Get(tx, store.Devices, k[len(user)+1:], d); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			return err
		}
		if d.UserId == string(user) {
			out = append(out, d)
		}
		return nil
	})
	return out, err
}

// forgetDevices removes every device of a user, in tx, as a recovery or a
// password change does (§5.1.10).
func forgetDevices(tx *bolt.Tx, user UserID) (int, error) {
	ds, err := userDevices(tx, user)
	if err != nil {
		return 0, err
	}
	for _, d := range ds {
		if err := deleteDevice(tx, d); err != nil {
			return 0, err
		}
	}
	return len(ds), nil
}

// Devices returns a user's registered devices, oldest first.
func (a *Auth) Devices(ctx context.Context, id UserID) ([]DeviceInfo, error) {
	if validID(id) != nil {
		return nil, nil
	}
	var out []DeviceInfo
	err := a.db.View(func(tx *bolt.Tx) error {
		ds, err := userDevices(tx, id)
		if err != nil {
			return err
		}
		now := a.now().UnixNano()
		for _, d := range ds {
			if now < d.Expires {
				out = append(out, DeviceInfo{
					ID: DeviceID(d.Id), Label: d.Label, Created: time.Unix(0, d.Created),
					Used: time.Unix(0, d.Used), Expires: time.Unix(0, d.Expires),
				})
			}
		}
		return nil
	})
	slices.SortFunc(out, func(x, y DeviceInfo) int { return x.Created.Compare(y.Created) })
	return out, err
}

// ForgetDevice removes one of a user's devices. An ID that isn't that
// user's does nothing.
func (a *Auth) ForgetDevice(ctx context.Context, user UserID, id DeviceID) error {
	var forgot bool
	err := a.db.Update(func(tx *bolt.Tx) error {
		d := new(storepb.Device)
		if err := store.Get(tx, store.Devices, []byte(id), d); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			return err
		}
		if d.UserId != string(user) {
			return nil
		}
		forgot = true
		return deleteDevice(tx, d)
	})
	if err == nil && forgot {
		a.record(ctx, Event{Kind: "device.removed", User: user, Reason: "forgotten"})
	}
	return err
}

// deviceCookie is the cookie that carries a device token.
func deviceCookie(token string, expires time.Time, insecure bool) *http.Cookie {
	return &http.Cookie{
		Name: cookieName("device", insecure), Value: token, Path: "/", Expires: expires,
		Secure: !insecure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}
}
