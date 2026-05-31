package app

import (
	"context"

	identitydomain "github.com/krishnaditya65/Project-Janus/internal/identity/domain"
)

type ListUsersUseCase struct {
	userRepo identitydomain.UserRepository
}

func NewListUsersUseCase(
	userRepo identitydomain.UserRepository,
) *ListUsersUseCase {

	return &ListUsersUseCase{
		userRepo: userRepo,
	}
}

func (u *ListUsersUseCase) Execute(
	ctx context.Context,
	tenantID string,
) ([]*identitydomain.User, error) {

	return u.userRepo.ListByTenant(
		ctx,
		tenantID,
	)
}
