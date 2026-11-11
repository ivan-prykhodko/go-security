package security

import (
	"context"

	"golang.org/x/sync/errgroup"
)

type AccessDecisionManager[S, O any] interface {
	Decide(ctx context.Context, subject S, attribute Attribute, object O) (Decision, error)
}

type accessDecisionManager[S, O any] struct {
	voters   Voters[S, O]
	strategy AccessDecisionStrategy
}

func NewAccessDecisionManager[S, O any](
	voters Voters[S, O],
	strategy AccessDecisionStrategy,
) AccessDecisionManager[S, O] {
	return &accessDecisionManager[S, O]{
		voters:   voters,
		strategy: strategy,
	}
}

func (dm *accessDecisionManager[S, O]) Decide(
	ctx context.Context,
	subject S,
	attribute Attribute,
	object O,
) (Decision, error) {
	voteDecisions, err := dm.collectDecisions(ctx, subject, attribute, object)
	if err != nil {
		return Decision{}, err
	}
	return dm.strategy.Decide(voteDecisions), nil
}

func (dm *accessDecisionManager[S, O]) collectDecisions(
	ctx context.Context,
	subject S,
	attribute Attribute,
	object O,
) ([]VoteDecision, error) {
	// TODO: what if one of the voters has higher priority than others?
	if len(dm.voters) == 0 {
		return []VoteDecision{}, nil
	}

	voters := make([]Voter[S, O], 0, len(dm.voters))
	for _, voter := range dm.voters {
		if voter.Supports(attribute, object) {
			voters = append(voters, voter)
		}
	}

	var voteDecisions = make([]VoteDecision, len(voters))
	eg, ctx := errgroup.WithContext(ctx)

	for i, voter := range voters {
		eg.Go(func() error {
			voteDecision, err := voter.Vote(ctx, subject, attribute, object)
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
