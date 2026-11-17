package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// keySet is the provider's key set (§5.14.5): fetched through the method's
// HTTP client, keeping only RSA keys of 2048 to 4096 bits and P-256 keys.
// A token no held key verifies brings a refetch, at most once a minute
// whether the last one worked or not; only a success replaces the keys.
// No lock is held across the network: concurrent callers share one fetch,
// which no caller's cancellation stops (review 0026).
type keySet struct {
	uri    string
	client *http.Client

	mu       sync.Mutex
	keys     []jose.JSONWebKey
	tried    time.Time // the last fetch, whatever its outcome
	inflight *fetchCall
}

type fetchCall struct {
	done chan struct{}
	err  error
}

// errKeys is a key set that couldn't be fetched: the method's own failure.
var errKeys = errors.New("oidc: the provider's keys couldn't be fetched")

// refetchEvery is a variable so tests can shorten it.
var refetchEvery = time.Minute

var algs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}

// usable keeps the keys a token may be signed with.
func usable(k jose.JSONWebKey) bool {
	if !k.Valid() || !k.IsPublic() {
		return false
	}
	if k.Use != "" && k.Use != "sig" {
		return false
	}
	switch pub := k.Key.(type) {
	case *rsa.PublicKey:
		if pub == nil || pub.N == nil {
			return false
		}
		n := pub.N.BitLen()
		return n >= 2048 && n <= 4096 && (k.Algorithm == "" || k.Algorithm == string(jose.RS256))
	case *ecdsa.PublicKey:
		return pub != nil && pub.Curve == elliptic.P256() && (k.Algorithm == "" || k.Algorithm == string(jose.ES256))
	}
	return false
}

// refresh fetches the key set, or waits for the fetch under way; it
// returns errKeys when the fetch failed, and nil when one isn't due.
func (s *keySet) refresh(ctx context.Context) error {
	s.mu.Lock()
	if c := s.inflight; c != nil {
		s.mu.Unlock()
		select {
		case <-c.done:
			return c.err
		case <-ctx.Done():
			return errKeys
		}
	}
	if !s.tried.IsZero() && time.Since(s.tried) < refetchEvery {
		s.mu.Unlock()
		return nil
	}
	c := &fetchCall{done: make(chan struct{})}
	s.inflight, s.tried = c, time.Now()
	s.mu.Unlock()

	keys, err := s.fetch(context.WithoutCancel(ctx))
	s.mu.Lock()
	if err == nil {
		s.keys = keys
	}
	c.err, s.inflight = err, nil
	s.mu.Unlock()
	close(c.done)
	return err
}

func (s *keySet) fetch(ctx context.Context) ([]jose.JSONWebKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.uri, nil)
	if err != nil {
		return nil, errKeys
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, errKeys
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errKeys
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, errKeys
	}
	var keep []jose.JSONWebKey
	for _, k := range set.Keys {
		if usable(k) {
			keep = append(keep, k)
		}
	}
	return keep, nil
}

// verify checks a compact token's signature with the keys held, then once
// more after a refetch when none verifies; it returns the payload.
func (s *keySet) verify(ctx context.Context, raw string) ([]byte, error) {
	jws, err := jose.ParseSignedCompact(raw, algs)
	if err != nil || len(jws.Signatures) != 1 {
		return nil, errors.New("oidc: not a compact token signed once with RS256 or ES256")
	}
	kid := jws.Signatures[0].Header.KeyID
	try := func() []byte {
		s.mu.Lock()
		held := slices.Clone(s.keys)
		s.mu.Unlock()
		for _, k := range held {
			if kid != "" && k.KeyID != kid {
				continue
			}
			if payload, err := jws.Verify(k.Key); err == nil {
				return payload
			}
		}
		return nil
	}
	if payload := try(); payload != nil {
		return payload, nil
	}
	if err := s.refresh(ctx); err != nil {
		return nil, err
	}
	if payload := try(); payload != nil {
		return payload, nil
	}
	return nil, errors.New("oidc: no key of the provider's verifies the token")
}

// callKeys is the key set as one Verify sees it: go-oidc formats a key
// set's error with %v, so the outage is kept here to answer it as the
// method's own failure, not a bad token (review 0026).
type callKeys struct {
	s      *keySet
	outage bool
}

func (c *callKeys) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	payload, err := c.s.verify(ctx, raw)
	if errors.Is(err, errKeys) {
		c.outage = true
	}
	return payload, err
}
