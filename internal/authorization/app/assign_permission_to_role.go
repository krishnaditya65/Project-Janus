package app

import (
	"context"

	authorizationdomain "github.com/krishnaditya65/Project-Janus/internal/authorization/domain"
	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
)

type AssignPermissionToRoleInput struct {
	TenantID       string
	RoleID         string
	PermissionName string
}

type AssignPermissionToRoleUseCase struct {
	roleRepo           authorizationdomain.RoleRepository
	permissionRepo     authorizationdomain.PermissionRepository
	rolePermissionRepo authorizationdomain.RolePermissionRepository
}

func NewAssignPermissionToRoleUseCase(
	roleRepo authorizationdomain.RoleRepository,
	permissionRepo authorizationdomain.PermissionRepository,
	rolePermissionRepo authorizationdomain.RolePermissionRepository,
) *AssignPermissionToRoleUseCase {

	return &AssignPermissionToRoleUseCase{
		roleRepo:           roleRepo,
		permissionRepo:     permissionRepo,
		rolePermissionRepo: rolePermissionRepo,
	}
}

func (u *AssignPermissionToRoleUseCase) Execute(
	ctx context.Context,
	input AssignPermissionToRoleInput,
) error {

	role, err := u.roleRepo.GetByID(
		ctx,
		input.RoleID,
	)

	if err != nil {
		return err
	}

	if role.TenantID != input.TenantID {
		return sharederrors.ErrForbidden
	}

	permission, err := u.permissionRepo.GetByName(
		ctx,
		input.PermissionName,
	)

	if err != nil {
		return err
	}

	return u.rolePermissionRepo.AssignPermission(
		ctx,
		&authorizationdomain.RolePermission{
			RoleID:       role.ID,
			PermissionID: permission.ID,
		},
	)
}
