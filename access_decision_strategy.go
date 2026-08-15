package security

type AccessDecisionStrategy interface {
	Decide([]VoteDecision) Decision
}

type Decision struct {
	State   AccessState
	Reasons []string
	Granted bool
}

type accessDecisionStrategy struct {
	stopOn                     AccessState
	atLeastOneOn               AccessState
	granted                    bool
	allowIfAllAbstainDecisions bool
}

func (s *accessDecisionStrategy) Decide(decisions []VoteDecision) Decision {
	reasons := make([]string, 0)
	for _, decision := range decisions {
		accessState := decision.State
		if accessState.Equal(s.stopOn) {
			return Decision{
				State:   s.stopOn,
				Reasons: []string{decision.Reason},
				Granted: s.granted,
			}
		}
		if accessState.Equal(s.atLeastOneOn) {
			reasons = append(reasons, decision.Reason)
		}
	}
	if len(reasons) > 0 {
		return Decision{
			State:   s.atLeastOneOn,
			Reasons: reasons,
			Granted: !s.granted,
		}
	}
	return Decision{
		State:   AccessAbstain,
		Reasons: []string{},
		Granted: s.allowIfAllAbstainDecisions,
	}
}

func NewAffirmativeStrategy(allowIfAllAbstainDecisions bool) AccessDecisionStrategy {
	return &accessDecisionStrategy{
		stopOn:                     AccessGranted,
		atLeastOneOn:               AccessDenied,
		granted:                    true,
		allowIfAllAbstainDecisions: allowIfAllAbstainDecisions,
	}
}

func NewUnanimousStrategy(allowIfAllAbstainDecisions bool) AccessDecisionStrategy {
	return &accessDecisionStrategy{
		stopOn:                     AccessDenied,
		atLeastOneOn:               AccessGranted,
		granted:                    false,
		allowIfAllAbstainDecisions: allowIfAllAbstainDecisions,
	}
}
