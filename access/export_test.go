package access

import bolt "go.etcd.io/bbolt"

// GrantUndeclared grants a group a key no code declares, as a permission
// removed from the code leaves its grants behind, and returns a handle for
// it the registry doesn't know. Test builds only.
func GrantUndeclared(ac *Access, g GroupID, key string) (*Perm, error) {
	err := ac.db.Update(func(tx *bolt.Tx) error { return b(tx, grantsB).Put(pair(string(g), key), nil) })
	return &Perm{key: key}, err
}

// Undeclare forgets a permission declared in a test, so the test can run
// again. Test builds only.
func Undeclare(p *Perm) {
	mu.Lock()
	defer mu.Unlock()
	delete(declared, p.key)
}
