package app

import (
	"context"
	"time"

	authdomain "github.com/krishnaditya65/Project-Janus/internal/authorization/domain"
	"github.com/krishnaditya65/Project-Janus/internal/shared/id"
)

type PermissionBootstrapService struct {
	permissionRepo     authdomain.PermissionRepository
	rolePermissionRepo authdomain.RolePermissionRepository
}

var tenantOwnerPermissions = []struct {
	Name        string
	Description string
}{
	{"users:create", "Create users"},
	{"users:read", "Read users"},
	{"users:update", "Update users"},
	{"users:delete", "Delete users"},

	{"roles:create", "Create roles"},
	{"roles:read", "Read roles"},
	{"roles:update", "Update roles"},
	{"roles:delete", "Delete roles"},

	{"tenant:update", "Update tenant"},
	{"tenant:delete", "Delete tenant"},
}

func NewPermissionBootstrapService(
	permissionRepo authdomain.PermissionRepository,
	rolePermissionRepo authdomain.RolePermissionRepository,
) *PermissionBootstrapService {

	return &PermissionBootstrapService{
		permissionRepo:     permissionRepo,
		rolePermissionRepo: rolePermissionRepo,
	}
}

func (s *PermissionBootstrapService) BootstrapTenantOwnerPermissions(
	ctx context.Context,
	roleID string,
) error {

	now := time.Now().UTC()

	for _, p := range tenantOwnerPermissions {

		permission, err :=
			s.permissionRepo.GetByName(
				ctx,
				p.Name,
			)

		if err != nil {

			permission = &authdomain.Permission{
				ID:          id.New(),
				Name:        p.Name,
				Description: p.Description,
				CreatedAt:   now,
			}

			err = s.permissionRepo.Create(
				ctx,
				permission,
			)

			if err != nil {
				return err
			}
		}

		err = s.rolePermissionRepo.AssignPermission(
			ctx,
			&authdomain.RolePermission{
				RoleID:       roleID,
				PermissionID: permission.ID,
			},
		)

		if err != nil {
			return err
		}
	}

	return nil
}
