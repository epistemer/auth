package oidc

import "time"

// SetRefetchEvery shortens the key set's refetch wait for a test.
func SetRefetchEvery(d time.Duration) (restore func()) {
	old := refetchEvery
	refetchEvery = d
	return func() { refetchEvery = old }
}
