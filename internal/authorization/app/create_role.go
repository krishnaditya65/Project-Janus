package app

import (
	"context"
	"time"

	authorizationdomain "github.com/krishnaditya65/Project-Janus/internal/authorization/domain"
	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
	"github.com/krishnaditya65/Project-Janus/internal/shared/id"
)

type CreateRoleInput struct {
	TenantID    string
	Name        string
	Description string
}

type CreateRoleUseCase struct {
	roleRepo authorizationdomain.RoleRepository
}

func NewCreateRoleUseCase(
	roleRepo authorizationdomain.RoleRepository,
) *CreateRoleUseCase {
	return &CreateRoleUseCase{
		roleRepo: roleRepo,
	}
}

func (u *CreateRoleUseCase) Execute(
	ctx context.Context,
	input CreateRoleInput,
) error {

	existingRole, err :=
		u.roleRepo.GetByTenantAndName(
			ctx,
			input.TenantID,
			input.Name,
		)

	if err == nil && existingRole != nil {
		return sharederrors.ErrConflict
	}

	role := &authorizationdomain.Role{
		ID:          id.New(),
		TenantID:    input.TenantID,
		Name:        input.Name,
		Description: input.Description,
		CreatedAt:   time.Now().UTC(),
	}

	return u.roleRepo.Create(
		ctx,
		role,
	)
}
