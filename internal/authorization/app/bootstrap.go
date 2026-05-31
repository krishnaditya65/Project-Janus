package app

import (
	"context"
	"time"

	authdomain "github.com/krishnaditya65/Project-Janus/internal/authorization/domain"
	"github.com/krishnaditya65/Project-Janus/internal/shared/id"
)

type BootstrapService struct {
	roleRepo authdomain.RoleRepository
}

func NewBootstrapService(
	roleRepo authdomain.RoleRepository,
) *BootstrapService {
	return &BootstrapService{
		roleRepo: roleRepo,
	}
}

func (s *BootstrapService) CreateTenantOwnerRole(
	ctx context.Context,
	tenantID string,
) (*authdomain.Role, error) {

	now := time.Now().UTC()

	role := &authdomain.Role{
		ID:          id.New(),
		TenantID:    tenantID,
		Name:        "tenant_owner",
		Description: "Tenant Owner",
		CreatedAt:   now,
	}

	err := s.roleRepo.Create(
		ctx,
		role,
	)

	if err != nil {
		return nil, err
	}

	return role, nil
}
