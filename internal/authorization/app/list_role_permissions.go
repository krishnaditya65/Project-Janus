package app

import (
	"context"

	authorizationdomain "github.com/krishnaditya65/Project-Janus/internal/authorization/domain"
	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
)

type ListRolePermissionsUseCase struct {
	roleRepo           authorizationdomain.RoleRepository
	rolePermissionRepo authorizationdomain.RolePermissionRepository
}

func NewListRolePermissionsUseCase(
	roleRepo authorizationdomain.RoleRepository,
	rolePermissionRepo authorizationdomain.RolePermissionRepository,
) *ListRolePermissionsUseCase {

	return &ListRolePermissionsUseCase{
		roleRepo:           roleRepo,
		rolePermissionRepo: rolePermissionRepo,
	}
}

func (u *ListRolePermissionsUseCase) Execute(
	ctx context.Context,
	tenantID string,
	roleID string,
) ([]string, error) {

	role, err := u.roleRepo.GetByID(
		ctx,
		roleID,
	)

	if err != nil {
		return nil, err
	}

	if role.TenantID != tenantID {
		return nil, sharederrors.ErrForbidden
	}

	return u.rolePermissionRepo.GetPermissionsForRole(
		ctx,
		roleID,
	)
}
