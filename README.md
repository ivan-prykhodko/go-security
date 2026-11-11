# Security

`security` is a Go package providing a foundation for building robust, voter-based authorization systems. It leverages modern Go features (Go 1.26+) and generics to provide a type-safe way to manage access control in your applications.

## What is it for?

This package provides an implementation of a voter-based access decision system. It allows you to decouple your authorization logic into small, reusable "Voters" and combine them using different strategies to make a final access decision.

## Features

- **Type-safe**: Uses Go generics to support any type for Subjects (actors, users, services) and Objects (resources being accessed).
- **Voter Architecture**: Add or remove authorization logic by implementing the `Voter` interface.
- **Flexible Strategies**: Choose between `Affirmative` (one "grant" is enough) or `Unanimous` (all must "grant") strategies.

## Installation

```bash
go get github.com/ivan-prykhodko/go-security
```

## Core Concepts

- **Attribute**: A string representing the action being performed (e.g., `"post.edit"`, `"user.create"`).
- **Voter**: A component that decides whether to grant, deny, or abstain from an access request based on the subject, attribute, and object.
- **AccessDecisionManager**: Orchestrates multiple voters and uses a `Strategy` to make the final decision.
- **AuthorizationChecker**: A higher-level service to check if access is granted.
- **Authorizer**: The primary entry point, which returns `security.AccessDeniedError` if access is not granted.

## Usage Example

Here's an example of how to implement authorization for a blog post using a custom authorizer struct (similar to the pattern in `example/main.go`):

```go
package main

import (
	"context"
	"fmt"

	"github.com/ivan-prykhodko/go-security"
)

type Actor struct {
	ID string
}

type Post struct {
	ID      int
	OwnerID string
}

const (
	PostCreateAttribute security.Attribute = "post.create"
	PostUpdateAttribute security.Attribute = "post.update"
)

// 1. Implement a Voter
type PostVoter struct{}

func (v PostVoter) Supports(attribute security.Attribute, object Post) bool {
	return attribute == PostCreateAttribute || attribute == PostUpdateAttribute
}

func (v PostVoter) Vote(ctx context.Context, subject Actor, attribute security.Attribute, object Post) (security.VoteDecision, error) {
	// Note: check if the subject has permissions, is owner, belongs to a tenancy, ReBAC, etc.
	return security.VoteDecision{
		State:  security.AccessGranted,
		Reason: "...",
	}, nil
}

// 2. Define a custom Authorizer struct
type PostAuthorizer struct {
	authorizer security.Authorizer[Actor, Post]
}

func NewPostAuthorizer() *PostAuthorizer {
	adm := security.NewAccessDecisionManager(
		security.Voters[Actor, Post]{&PostVoter{}},
		security.NewUnanimousStrategy(false),
	)
	authChecker := security.NewAuthorizationChecker(adm)
	return &PostAuthorizer{
		authorizer: security.NewAuthorizer(authChecker),
	}
}

func (a *PostAuthorizer) AuthorizeCreate(ctx context.Context, subject Actor, object Post) error {
	return a.authorizer.Authorize(ctx, subject, PostCreateAttribute, object)
}

func (a *PostAuthorizer) AuthorizeUpdate(ctx context.Context, subject Actor, object Post) error {
	return a.authorizer.Authorize(ctx, subject, PostUpdateAttribute, object)
}

func main() {
	ctx := context.Background()
	actor := Actor{ID: "user-1"}
	post := Post{ID: 101, OwnerID: "user-1"}

	// 3. Setup and use the PostAuthorizer
	postAuthorizer := NewPostAuthorizer()

	if err := postAuthorizer.AuthorizeUpdate(ctx, actor, post); err != nil {
		fmt.Printf("Access denied: %v\n", err)
		return
	}
	fmt.Println("Access granted!")
}
```

## License

This project is licensed under the [LICENSE](LICENSE) file.
