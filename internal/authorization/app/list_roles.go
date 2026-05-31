package app

import (
	"context"

	authorizationdomain "github.com/krishnaditya65/Project-Janus/internal/authorization/domain"
)

type ListRolesUseCase struct {
	roleRepo authorizationdomain.RoleRepository
}

func NewListRolesUseCase(
	roleRepo authorizationdomain.RoleRepository,
) *ListRolesUseCase {
	return &ListRolesUseCase{
		roleRepo: roleRepo,
	}
}

func (u *ListRolesUseCase) Execute(
	ctx context.Context,
	tenantID string,
) ([]*authorizationdomain.Role, error) {

	return u.roleRepo.ListByTenant(
		ctx,
		tenantID,
	)
}
