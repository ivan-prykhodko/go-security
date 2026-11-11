package main

import (
	"context"

	"github.com/ivan-prykhodko/go-security"
)

const (
	PostCreateAttribute security.Attribute = "user.create"
	PostUpdateAttribute security.Attribute = "user.update"
	PostDeleteAttribute security.Attribute = "user.delete"
)

func main() {
	ctx := context.Background()
	actor := Actor{ID: "123"}
	post := Post{ID: 1, Name: "Post 1"}

	postAuthorizer := NewPostAuthorizer()
	if err := postAuthorizer.AuthorizeCreate(ctx, actor, post); err != nil {
		panic(err)
	}
}

type Actor struct {
	ID string
}

type Post struct {
	ID   int
	Name string
}

func NewPostAuthorizer() *PostAuthorizer {
	postVoter := NewPostVoter()
	adm := security.NewAccessDecisionManager(
		security.Voters[Actor, Post]{
			postVoter,
		},
		security.NewUnanimousStrategy(false),
	)
	authChecker := security.NewAuthorizationChecker(adm)
	authorizer := security.NewAuthorizer(authChecker)

	return &PostAuthorizer{
		authorizer: authorizer,
	}
}

type PostAuthorizer struct {
	authorizer security.Authorizer[Actor, Post]
}

func (a *PostAuthorizer) AuthorizeCreate(ctx context.Context, subject Actor, object Post) error {
	// Note: other security policies
	return a.authorizer.Authorize(ctx, subject, PostCreateAttribute, object)
}

func (a *PostAuthorizer) AuthorizeUpdate(ctx context.Context, subject Actor, object Post) error {
	// Note: other security policies
	return a.authorizer.Authorize(ctx, subject, PostUpdateAttribute, object)
}

type PostVoter struct {
}

func NewPostVoter() security.Voter[Actor, Post] {
	return &PostVoter{}
}

func (v PostVoter) Supports(attribute security.Attribute, object Post) bool {
	return attribute == PostUpdateAttribute ||
		attribute == PostCreateAttribute ||
		attribute == PostDeleteAttribute
}

func (v PostVoter) Vote(
	ctx context.Context,
	subject Actor,
	attribute security.Attribute,
	object Post,
) (security.VoteDecision, error) {
	// Note: check if the subject has permissions, is owner, belongs to a tenancy, ReBAC, etc.
	return security.VoteDecision{
		State:  security.AccessGranted,
		Reason: "...",
	}, nil
}
