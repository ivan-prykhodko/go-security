package security

import "context"

type AuthorizationChecker[A, T any] interface {
	IsGranted(ctx context.Context, actor A, attribute Attribute, subject T) (bool, error)
}

type authorizationChecker[A, T any] struct {
	adm AccessDecisionManager[A, T]
}

func NewAuthorizationChecker[A, T any](adm AccessDecisionManager[A, T]) AuthorizationChecker[A, T] {
	return &authorizationChecker[A, T]{
		adm: adm,
	}
}

func (a *authorizationChecker[A, T]) IsGranted(ctx context.Context, actor A, attribute Attribute, subject T) (bool, error) {
	decision, err := a.adm.Decide(ctx, actor, attribute, subject)
	if err != nil {
		return false, err
	}
	// TODO: log decision if needed
	return decision.Granted, nil
}
