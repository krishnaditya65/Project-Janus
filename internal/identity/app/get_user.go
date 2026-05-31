package app

import (
	"context"

	identitydomain "github.com/krishnaditya65/Project-Janus/internal/identity/domain"
)

type GetUserInput struct {
	TenantID string
	UserID   string
}

type GetUserUseCase struct {
	userRepo identitydomain.UserRepository
}

func NewGetUserUseCase(
	userRepo identitydomain.UserRepository,
) *GetUserUseCase {

	return &GetUserUseCase{
		userRepo: userRepo,
	}
}

func (u *GetUserUseCase) Execute(
	ctx context.Context,
	input GetUserInput,
) (*identitydomain.User, error) {

	return u.userRepo.GetByTenantAndID(
		ctx,
		input.TenantID,
		input.UserID,
	)
}
