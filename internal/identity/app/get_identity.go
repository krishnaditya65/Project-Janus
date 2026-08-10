package app

import (
	"context"

	identitydomain "github.com/krishnaditya65/Project-Janus/internal/identity/domain"
)

// GetIdentityByEmailUseCase and GetIdentityByIDUseCase expose
// identitydomain.Repository's read methods at the app layer so identity's
// own HTTP transport (and, by extension, identity-service) can serve them
// over the network. auth's login flow in particular needs GetByEmail before
// a principal exists, so this has no authorization concern of its own -
// callers are expected to be trusted internal services.

type GetIdentityByEmailInput struct {
	Email string
}

type GetIdentityByEmailUseCase struct {
	repo identitydomain.Repository
}

func NewGetIdentityByEmailUseCase(
	repo identitydomain.Repository,
) *GetIdentityByEmailUseCase {

	return &GetIdentityByEmailUseCase{
		repo: repo,
	}
}

func (u *GetIdentityByEmailUseCase) Execute(
	ctx context.Context,
	input GetIdentityByEmailInput,
) (*identitydomain.Identity, error) {

	return u.repo.GetByEmail(ctx, input.Email)
}

type GetIdentityByIDInput struct {
	ID string
}

type GetIdentityByIDUseCase struct {
	repo identitydomain.Repository
}

func NewGetIdentityByIDUseCase(
	repo identitydomain.Repository,
) *GetIdentityByIDUseCase {

	return &GetIdentityByIDUseCase{
		repo: repo,
	}
}

func (u *GetIdentityByIDUseCase) Execute(
	ctx context.Context,
	input GetIdentityByIDInput,
) (*identitydomain.Identity, error) {

	return u.repo.GetByID(ctx, input.ID)
}
