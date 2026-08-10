package app

import (
	"context"

	identitydomain "github.com/krishnaditya65/Project-Janus/internal/identity/domain"
)

// DeleteIdentityUseCase exposes identitydomain.Repository.Delete at the app
// layer so identity-service's HTTP transport can serve it over the network.
// It backs the compensating-delete path callers (e.g. auth's
// RegisterUseCase, identity's own CreateUserUseCase) use when an Identity
// was persisted here but a subsequent step in the caller's local
// transaction failed - see internal/identity/infra/httpclient's Delete for
// the client side of this call.
type DeleteIdentityInput struct {
	ID string
}

type DeleteIdentityUseCase struct {
	repo identitydomain.Repository
}

func NewDeleteIdentityUseCase(
	repo identitydomain.Repository,
) *DeleteIdentityUseCase {

	return &DeleteIdentityUseCase{
		repo: repo,
	}
}

func (u *DeleteIdentityUseCase) Execute(
	ctx context.Context,
	input DeleteIdentityInput,
) error {

	return u.repo.Delete(ctx, input.ID)
}
