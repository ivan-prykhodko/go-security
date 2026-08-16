package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAffirmativeStrategy(t *testing.T) {
	tests := []struct {
		name                       string
		allowIfAllAbstainDecisions bool
		decisions                  []VoteDecision
		expectedGranted            bool
		expectedState              AccessState
		expectedReasons            []string
	}{
		{
			name:                       "At least one granted",
			allowIfAllAbstainDecisions: false,
			decisions: []VoteDecision{
				{State: AccessDenied, Reason: "denied 1"},
				{State: AccessGranted, Reason: "granted 1"},
				{State: AccessAbstain, Reason: "abstain 1"},
			},
			expectedGranted: true,
			expectedState:   AccessGranted,
			expectedReasons: []string{"granted 1"},
		},
		{
			name:                       "Multiple denied, collect all reasons",
			allowIfAllAbstainDecisions: false,
			decisions: []VoteDecision{
				{State: AccessDenied, Reason: "denied 1"},
				{State: AccessDenied, Reason: "denied 2"},
			},
			expectedGranted: false,
			expectedState:   AccessDenied,
			expectedReasons: []string{"denied 1", "denied 2"},
		},
		{
			name:                       "All abstain, allow false",
			allowIfAllAbstainDecisions: false,
			decisions: []VoteDecision{
				{State: AccessAbstain, Reason: "abstain 1"},
			},
			expectedGranted: false,
			expectedState:   AccessAbstain,
			expectedReasons: []string{},
		},
		{
			name:                       "All abstain, allow true",
			allowIfAllAbstainDecisions: true,
			decisions: []VoteDecision{
				{State: AccessAbstain, Reason: "abstain 1"},
			},
			expectedGranted: true,
			expectedState:   AccessAbstain,
			expectedReasons: []string{},
		},
		{
			name:                       "Empty decisions, allow false",
			allowIfAllAbstainDecisions: false,
			decisions:                  []VoteDecision{},
			expectedGranted:            false,
			expectedState:              AccessAbstain,
			expectedReasons:            []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := NewAffirmativeStrategy(tt.allowIfAllAbstainDecisions)
			decision := strategy.Decide(tt.decisions)
			assert.Equal(t, tt.expectedGranted, decision.Granted)
			assert.Equal(t, tt.expectedState, decision.State)
			assert.Equal(t, tt.expectedReasons, decision.Reasons)
		})
	}
}

func TestUnanimousStrategy(t *testing.T) {
	tests := []struct {
		name                       string
		allowIfAllAbstainDecisions bool
		decisions                  []VoteDecision
		expectedGranted            bool
		expectedState              AccessState
		expectedReasons            []string
	}{
		{
			name:                       "All granted",
			allowIfAllAbstainDecisions: false,
			decisions: []VoteDecision{
				{State: AccessGranted, Reason: "granted 1"},
				{State: AccessGranted, Reason: "granted 2"},
			},
			expectedGranted: true,
			expectedState:   AccessGranted,
			expectedReasons: []string{"granted 1", "granted 2"},
		},
		{
			name:                       "At least one denied",
			allowIfAllAbstainDecisions: false,
			decisions: []VoteDecision{
				{State: AccessGranted, Reason: "granted 1"},
				{State: AccessDenied, Reason: "denied 1"},
				{State: AccessGranted, Reason: "granted 2"},
			},
			expectedGranted: false,
			expectedState:   AccessDenied,
			expectedReasons: []string{"denied 1"},
		},
		{
			name:                       "All abstain, allow false",
			allowIfAllAbstainDecisions: false,
			decisions: []VoteDecision{
				{State: AccessAbstain, Reason: "abstain 1"},
			},
			expectedGranted: false,
			expectedState:   AccessAbstain,
			expectedReasons: []string{},
		},
		{
			name:                       "All abstain, allow true",
			allowIfAllAbstainDecisions: true,
			decisions: []VoteDecision{
				{State: AccessAbstain, Reason: "abstain 1"},
			},
			expectedGranted: true,
			expectedState:   AccessAbstain,
			expectedReasons: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := NewUnanimousStrategy(tt.allowIfAllAbstainDecisions)
			decision := strategy.Decide(tt.decisions)
			assert.Equal(t, tt.expectedGranted, decision.Granted)
			assert.Equal(t, tt.expectedState, decision.State)
			assert.Equal(t, tt.expectedReasons, decision.Reasons)
		})
	}
}
