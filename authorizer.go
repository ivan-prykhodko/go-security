package security

import "context"

type Authorizer[S, O any] interface {
	Authorize(ctx context.Context, subject S, attribute Attribute, object O) error
}

type authorizer[S, O any] struct {
	authChecker AuthorizationChecker[S, O]
}

func NewAuthorizer[S, O any](authChecker AuthorizationChecker[S, O]) Authorizer[S, O] {
	return &authorizer[S, O]{
		authChecker: authChecker,
	}
}

func (a authorizer[S, O]) Authorize(ctx context.Context, subject S, attribute Attribute, object O) error {
	granted, reasons, err := a.authChecker.IsGranted(ctx, subject, attribute, object)
	if err != nil {
		return err
	}
	if !granted {
		return NewAccessDeniedError(reasons)
	}
	return nil
}
