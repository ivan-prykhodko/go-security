package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAccessState_Equal(t *testing.T) {
	tests := []struct {
		name     string
		a        AccessState
		b        AccessState
		expected bool
	}{
		{"Granted equal Granted", AccessGranted, AccessGranted, true},
		{"Granted not equal Denied", AccessGranted, AccessDenied, false},
		{"Denied equal Denied", AccessDenied, AccessDenied, true},
		{"Abstain equal Abstain", AccessAbstain, AccessAbstain, true},
		{"Abstain not equal Granted", AccessAbstain, AccessGranted, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.a.Equal(tt.b))
		})
	}
}
