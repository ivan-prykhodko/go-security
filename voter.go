package security

import "context"

type Voters[S, O any] []Voter[S, O]

type Voter[S, O any] interface {
	Vote(ctx context.Context, subject S, attribute Attribute, object O) (VoteDecision, error)
	Supports(permission Attribute, object O) bool
}

type VoteDecision struct {
	State  AccessState
	Reason string
}
