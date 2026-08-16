package security

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockAuthorizationChecker[A, T any] struct {
	mock.Mock
}

func (m *MockAuthorizationChecker[A, T]) IsGranted(ctx context.Context, actor A, attribute Attribute, subject T) (bool, error) {
	args := m.Called(ctx, actor, attribute, subject)
	return args.Bool(0), args.Error(1)
}

func TestAuthorizer_Authorize(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockChecker := new(MockAuthorizationChecker[Actor, Post])
		actor := Actor{ID: "user1"}
		post := Post{ID: 1, Name: "doc1"}
		mockChecker.On("IsGranted", mock.Anything, actor, "read", post).Return(true, nil)

		authorizer := NewAuthorizer[Actor, Post](mockChecker)
		err := authorizer.Authorize(t.Context(), actor, "read", post)

		assert.NoError(t, err)
		mockChecker.AssertExpectations(t)
	})

	t.Run("Access Denied", func(t *testing.T) {
		mockChecker := new(MockAuthorizationChecker[Actor, Post])
		actor := Actor{ID: "user1"}
		post := Post{ID: 1, Name: "doc1"}
		mockChecker.On("IsGranted", mock.Anything, actor, "read", post).Return(false, nil)

		authorizer := NewAuthorizer[Actor, Post](mockChecker)
		err := authorizer.Authorize(t.Context(), actor, "read", post)

		assert.ErrorIs(t, err, ErrAccessDenied)
		mockChecker.AssertExpectations(t)
	})

	t.Run("Error", func(t *testing.T) {
		mockChecker := new(MockAuthorizationChecker[Actor, Post])
		actor := Actor{ID: "user1"}
		post := Post{ID: 1, Name: "doc1"}
		expectedErr := errors.New("checker error")
		mockChecker.On("IsGranted", mock.Anything, actor, "read", post).Return(false, expectedErr)

		authorizer := NewAuthorizer[Actor, Post](mockChecker)
		err := authorizer.Authorize(t.Context(), actor, "read", post)

		assert.ErrorIs(t, err, expectedErr)
		mockChecker.AssertExpectations(t)
	})
}
