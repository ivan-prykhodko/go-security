package security

import "context"

type AuthorizationChecker[S, O any] interface {
	IsGranted(ctx context.Context, subject S, attribute Attribute, object O) (bool, []string, error)
}

type authorizationChecker[S, O any] struct {
	adm AccessDecisionManager[S, O]
}

func NewAuthorizationChecker[S, O any](adm AccessDecisionManager[S, O]) AuthorizationChecker[S, O] {
	return &authorizationChecker[S, O]{
		adm: adm,
	}
}

func (a *authorizationChecker[S, O]) IsGranted(
	ctx context.Context,
	subject S,
	attribute Attribute,
	object O,
) (bool, []string, error) {
	decision, err := a.adm.Decide(ctx, subject, attribute, object)
	if err != nil {
		return false, nil, err
	}
	return decision.Granted, decision.Reasons, nil
}
