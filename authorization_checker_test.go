package security

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockAccessDecisionManager[A, T any] struct {
	mock.Mock
}

func (m *MockAccessDecisionManager[A, T]) Decide(ctx context.Context, actor A, attribute Attribute, subject T) (Decision, error) {
	args := m.Called(ctx, actor, attribute, subject)
	return args.Get(0).(Decision), args.Error(1)
}

func TestAuthorizationChecker_IsGranted(t *testing.T) {
	t.Run("Granted", func(t *testing.T) {
		mockADM := new(MockAccessDecisionManager[Actor, Post])
		actor := Actor{ID: "user1"}
		post := Post{ID: 1, Name: "doc1"}
		mockADM.On("Decide", mock.Anything, actor, "read", post).Return(Decision{Granted: true}, nil)

		checker := NewAuthorizationChecker[Actor, Post](mockADM)
		granted, err := checker.IsGranted(t.Context(), actor, "read", post)

		assert.NoError(t, err)
		assert.True(t, granted)
		mockADM.AssertExpectations(t)
	})

	t.Run("Denied", func(t *testing.T) {
		mockADM := new(MockAccessDecisionManager[Actor, Post])
		actor := Actor{ID: "user1"}
		post := Post{ID: 1, Name: "doc1"}
		mockADM.On("Decide", mock.Anything, actor, "read", post).Return(Decision{Granted: false}, nil)

		checker := NewAuthorizationChecker[Actor, Post](mockADM)
		granted, err := checker.IsGranted(t.Context(), actor, "read", post)

		assert.NoError(t, err)
		assert.False(t, granted)
		mockADM.AssertExpectations(t)
	})

	t.Run("Error", func(t *testing.T) {
		mockADM := new(MockAccessDecisionManager[Actor, Post])
		actor := Actor{ID: "user1"}
		post := Post{ID: 1, Name: "doc1"}
		expectedErr := errors.New("adm error")
		mockADM.On("Decide", mock.Anything, actor, "read", post).Return(Decision{}, expectedErr)

		checker := NewAuthorizationChecker[Actor, Post](mockADM)
		_, err := checker.IsGranted(t.Context(), actor, "read", post)

		assert.ErrorIs(t, err, expectedErr)
		mockADM.AssertExpectations(t)
	})
}
