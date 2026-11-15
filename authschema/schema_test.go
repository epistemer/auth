package authschema

import "testing"

// The group is checked end to end by internal/testapp, whose generated
// settings must satisfy auth.Config.
func TestGroup(t *testing.T) {
	if Group() == nil {
		t.Fatal("Group returned nil")
	}
}
