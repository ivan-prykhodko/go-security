package security

import "context"

type Authorizer[A, T any] interface {
	Authorize(ctx context.Context, actor A, attribute Attribute, subject T) error
}

type authorizer[A, T any] struct {
	authChecker AuthorizationChecker[A, T]
}

func NewAuthorizer[A, T any](authChecker AuthorizationChecker[A, T]) Authorizer[A, T] {
	return &authorizer[A, T]{
		authChecker: authChecker,
	}
}

func (a authorizer[A, T]) Authorize(ctx context.Context, actor A, attribute Attribute, subject T) error {
	granted, err := a.authChecker.IsGranted(ctx, actor, attribute, subject)
	if err != nil {
		return err
	}
	if !granted {
		return ErrAccessDenied
	}
	return nil
}
