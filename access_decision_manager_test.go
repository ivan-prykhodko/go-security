package security

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockVoter[A, T any] struct {
	mock.Mock
}

func (m *MockVoter[A, T]) Vote(ctx context.Context, actor A, attribute Attribute, subject T) (VoteDecision, error) {
	args := m.Called(ctx, actor, attribute, subject)
	return args.Get(0).(VoteDecision), args.Error(1)
}

func (m *MockVoter[A, T]) Supports(permission Attribute, subject T) bool {
	args := m.Called(permission, subject)
	return args.Bool(0)
}

func TestAccessDecisionManager_Decide(t *testing.T) {
	t.Run("Success path", func(t *testing.T) {
		mockVoter := new(MockVoter[Actor, Post])
		actor := Actor{ID: "user1"}
		post := Post{ID: 1, Name: "doc1"}
		mockVoter.On("Supports", "read", post).Return(true)
		mockVoter.On("Vote", mock.Anything, actor, "read", post).Return(VoteDecision{State: AccessGranted, Reason: "allowed"}, nil)

		strategy := NewAffirmativeStrategy(false)
		adm := NewAccessDecisionManager[Actor, Post](Voters[Actor, Post]{mockVoter}, strategy)

		decision, err := adm.Decide(t.Context(), actor, "read", post)
		assert.NoError(t, err)
		assert.True(t, decision.Granted)
		assert.Equal(t, AccessGranted, decision.State)
		mockVoter.AssertExpectations(t)
	})

	t.Run("Voter error", func(t *testing.T) {
		mockVoter := new(MockVoter[Actor, Post])
		actor := Actor{ID: "user1"}
		post := Post{ID: 1, Name: "doc1"}
		expectedErr := errors.New("voter error")
		mockVoter.On("Supports", "read", post).Return(true)
		mockVoter.On("Vote", mock.Anything, actor, "read", post).Return(VoteDecision{}, expectedErr)

		strategy := NewAffirmativeStrategy(false)
		adm := NewAccessDecisionManager[Actor, Post](Voters[Actor, Post]{mockVoter}, strategy)

		_, err := adm.Decide(t.Context(), actor, "read", post)
		assert.ErrorIs(t, err, expectedErr)
		mockVoter.AssertExpectations(t)
	})

	t.Run("Multiple voters - concurrency check", func(t *testing.T) {
		mockVoter1 := new(MockVoter[Actor, Post])
		mockVoter2 := new(MockVoter[Actor, Post])
		actor := Actor{ID: "user1"}
		post := Post{ID: 1, Name: "doc1"}

		mockVoter1.On("Supports", "read", post).Return(true)
		mockVoter2.On("Supports", "read", post).Return(true)

		mockVoter1.On("Vote", mock.Anything, actor, "read", post).Run(func(args mock.Arguments) {
			time.Sleep(10 * time.Millisecond)
		}).Return(VoteDecision{State: AccessDenied, Reason: "denied 1"}, nil)

		mockVoter2.On("Vote", mock.Anything, actor, "read", post).Return(VoteDecision{State: AccessGranted, Reason: "allowed 2"}, nil)

		strategy := NewAffirmativeStrategy(false)
		adm := NewAccessDecisionManager[Actor, Post](Voters[Actor, Post]{mockVoter1, mockVoter2}, strategy)

		decision, err := adm.Decide(t.Context(), actor, "read", post)
		assert.NoError(t, err)
		assert.True(t, decision.Granted)
		assert.Equal(t, AccessGranted, decision.State)
		mockVoter1.AssertExpectations(t)
		mockVoter2.AssertExpectations(t)
	})

	t.Run("Empty voters", func(t *testing.T) {
		strategy := NewAffirmativeStrategy(false)
		adm := NewAccessDecisionManager[Actor, Post](Voters[Actor, Post]{}, strategy)

		decision, err := adm.Decide(t.Context(), Actor{ID: "user1"}, "read", Post{ID: 1, Name: "doc1"})
		assert.NoError(t, err)
		assert.False(t, decision.Granted)
		assert.Equal(t, AccessAbstain, decision.State)
	})

	t.Run("Unsupported attribute", func(t *testing.T) {
		mockVoter := new(MockVoter[Actor, Post])
		actor := Actor{ID: "user1"}
		post := Post{ID: 1, Name: "doc1"}
		mockVoter.On("Supports", "write", post).Return(false)

		strategy := NewAffirmativeStrategy(false)
		adm := NewAccessDecisionManager[Actor, Post](Voters[Actor, Post]{mockVoter}, strategy)

		decision, err := adm.Decide(t.Context(), actor, "write", post)
		assert.NoError(t, err)
		assert.False(t, decision.Granted)
		assert.Equal(t, AccessAbstain, decision.State)
		mockVoter.AssertExpectations(t)
	})

	t.Run("Context cancellation", func(t *testing.T) {
		mockVoter := new(MockVoter[Actor, Post])
		actor := Actor{ID: "user1"}
		post := Post{ID: 1, Name: "doc1"}
		mockVoter.On("Supports", "read", post).Return(true)

		// Wait for context cancellation
		mockVoter.On("Vote", mock.Anything, actor, "read", post).Run(func(args mock.Arguments) {
			ctx := args.Get(0).(context.Context)
			<-ctx.Done()
		}).Return(VoteDecision{}, context.Canceled)

		strategy := NewAffirmativeStrategy(false)
		adm := NewAccessDecisionManager[Actor, Post](Voters[Actor, Post]{mockVoter}, strategy)

		ctx, cancel := context.WithCancel(t.Context())
		cancel() // Cancel immediately

		_, err := adm.Decide(ctx, actor, "read", post)
		assert.ErrorIs(t, err, context.Canceled)
	})
}
