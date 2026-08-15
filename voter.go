package security

import "context"

type Voters[A, T any] []Voter[A, T]

type Voter[A, T any] interface {
	Vote(ctx context.Context, actor A, attribute Attribute, subject T) (VoteDecision, error)
	Supports(permission Attribute, subject T) bool
}

type VoteDecision struct {
	State  AccessState
	Reason string
}
