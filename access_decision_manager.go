package security

import (
	"context"

	"golang.org/x/sync/errgroup"
)

type AccessDecisionManager[A, T any] interface {
	Decide(ctx context.Context, actor A, attribute Attribute, subject T) (Decision, error)
}

type accessDecisionManager[A, T any] struct {
	voters   Voters[A, T]
	strategy AccessDecisionStrategy
}

func NewAccessDecisionManager[A, T any](voters Voters[A, T], strategy AccessDecisionStrategy) AccessDecisionManager[A, T] {
	return &accessDecisionManager[A, T]{
		voters:   voters,
		strategy: strategy,
	}
}

func (dm *accessDecisionManager[A, T]) Decide(ctx context.Context, actor A, attribute Attribute, subject T) (Decision, error) {
	voteDecisions, err := dm.collectDecisions(ctx, actor, attribute, subject)
	if err != nil {
		return Decision{}, err
	}
	return dm.strategy.Decide(voteDecisions), nil
}

func (dm *accessDecisionManager[A, T]) collectDecisions(ctx context.Context, actor A, attribute Attribute, subject T) ([]VoteDecision, error) {
	// TODO: what if one of the voters has higher priority than others?
	if len(dm.voters) == 0 {
		return []VoteDecision{}, nil
	}

	voters := make([]Voter[A, T], 0, len(dm.voters))
	for _, voter := range dm.voters {
		if voter.Supports(attribute, subject) {
			voters = append(voters, voter)
		}
	}

	var voteDecisions = make([]VoteDecision, len(voters))
	eg, ctx := errgroup.WithContext(ctx)

	for i, voter := range voters {
		eg.Go(func() error {
			voteDecision, err := voter.Vote(ctx, actor, attribute, subject)
			if err != nil {
				return err
			}
			voteDecisions[i] = voteDecision
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}

	return voteDecisions, nil
}
