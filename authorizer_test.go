package security

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockAuthorizationChecker[S, O any] struct {
	mock.Mock
}

func (m *MockAuthorizationChecker[S, O]) IsGranted(
	ctx context.Context,
	subject S,
	attribute Attribute,
	object O,
) (bool, []string, error) {
	args := m.Called(ctx, subject, attribute, object)
	var reasons []string
	if args.Get(1) != nil {
		reasons = args.Get(1).([]string)
	}
	return args.Bool(0), reasons, args.Error(2)
}

func TestAuthorizer_Authorize(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockChecker := new(MockAuthorizationChecker[Actor, Post])
		actor := Actor{ID: "user1"}
		post := Post{ID: 1, Name: "doc1"}
		mockChecker.On("IsGranted", mock.Anything, actor, "read", post).
			Return(true, nil, nil)

		authorizer := NewAuthorizer[Actor, Post](mockChecker)
		err := authorizer.Authorize(t.Context(), actor, "read", post)

		assert.NoError(t, err)
		mockChecker.AssertExpectations(t)
	})

	t.Run("Access Denied", func(t *testing.T) {
		mockChecker := new(MockAuthorizationChecker[Actor, Post])
		actor := Actor{ID: "user1"}
		post := Post{ID: 1, Name: "doc1"}
		mockChecker.On("IsGranted", mock.Anything, actor, "read", post).
			Return(false, []string{"some reason"}, nil)

		authorizer := NewAuthorizer[Actor, Post](mockChecker)
		err := authorizer.Authorize(t.Context(), actor, "read", post)

		var accessDeniedError *AccessDeniedError
		assert.ErrorAs(t, err, &accessDeniedError)
		mockChecker.AssertExpectations(t)
	})

	t.Run("Error", func(t *testing.T) {
		mockChecker := new(MockAuthorizationChecker[Actor, Post])
		actor := Actor{ID: "user1"}
		post := Post{ID: 1, Name: "doc1"}
		expectedErr := errors.New("checker error")
		mockChecker.On("IsGranted", mock.Anything, actor, "read", post).
			Return(false, nil, expectedErr)

		authorizer := NewAuthorizer[Actor, Post](mockChecker)
		err := authorizer.Authorize(t.Context(), actor, "read", post)

		assert.ErrorIs(t, err, expectedErr)
		mockChecker.AssertExpectations(t)
	})
}
