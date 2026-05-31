package app

import (
	"context"
	"time"

	"github.com/krishnaditya65/Project-Janus/internal/identity/domain"
	"github.com/krishnaditya65/Project-Janus/internal/shared/id"
)

type CreateIdentityInput struct {
	Email string
}

type CreateIdentityUseCase struct {
	repo domain.Repository
}

func NewCreateIdentityUseCase(
	repo domain.Repository,
) *CreateIdentityUseCase {
	return &CreateIdentityUseCase{
		repo: repo,
	}
}

func (u *CreateIdentityUseCase) Execute(
	ctx context.Context,
	input CreateIdentityInput,
) (*domain.Identity, error) {
	now := time.Now().UTC()

	identity := &domain.Identity{
		ID:            id.New(),
		PrimaryEmail:  input.Email,
		EmailVerified: false,
		Status:        "active",
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := u.repo.Create(ctx, identity); err != nil {
		return nil, err
	}

	return identity, nil
}
