package app

import (
	"context"
	"time"

	authdomain "github.com/krishnaditya65/Project-Janus/internal/auth/domain"
	identitydomain "github.com/krishnaditya65/Project-Janus/internal/identity/domain"

	"github.com/krishnaditya65/Project-Janus/internal/shared/id"
	"github.com/krishnaditya65/Project-Janus/internal/shared/password"
	"github.com/krishnaditya65/Project-Janus/internal/shared/slug"
	"github.com/krishnaditya65/Project-Janus/internal/shared/tx"

	authorizationapp "github.com/krishnaditya65/Project-Janus/internal/authorization/app"

	tenantapp "github.com/krishnaditya65/Project-Janus/internal/tenant/app"
	tenantdomain "github.com/krishnaditya65/Project-Janus/internal/tenant/domain"

	authorizationdomain "github.com/krishnaditya65/Project-Janus/internal/authorization/domain"
)

type RegisterInput struct {
	Email    string
	Password string
}

type RegisterUseCase struct {
	txManager tx.Manager

	identityRepo   identitydomain.Repository
	credentialRepo authdomain.Repository

	tenantRepo tenantdomain.Repository
	userRepo   identitydomain.UserRepository

	slugService *tenantapp.SlugService

	userRoleRepo     authorizationdomain.UserRoleRepository
	bootstrapService *authorizationapp.BootstrapService

	permissionBootstrapService *authorizationapp.PermissionBootstrapService
}

func NewRegisterUseCase(
	txManager tx.Manager,
	identityRepo identitydomain.Repository,
	credentialRepo authdomain.Repository,
	tenantRepo tenantdomain.Repository,
	userRepo identitydomain.UserRepository,
	slugService *tenantapp.SlugService,
	userRoleRepo authorizationdomain.UserRoleRepository,
	bootstrapService *authorizationapp.BootstrapService,
	permissionBootstrapService *authorizationapp.PermissionBootstrapService,
) *RegisterUseCase {

	return &RegisterUseCase{
		txManager: txManager,

		identityRepo:   identityRepo,
		credentialRepo: credentialRepo,

		tenantRepo: tenantRepo,
		userRepo:   userRepo,

		slugService: slugService,

		userRoleRepo:     userRoleRepo,
		bootstrapService: bootstrapService,

		permissionBootstrapService: permissionBootstrapService,
	}
}
func (u *RegisterUseCase) Execute(
	ctx context.Context,
	input RegisterInput,
) error {
	return u.txManager.WithinTransaction(
		ctx,
		func(txCtx context.Context) error {
			now := time.Now().UTC()

			identity := &identitydomain.Identity{
				ID:            id.New(),
				PrimaryEmail:  input.Email,
				EmailVerified: false,
				Status:        "active",
				CreatedAt:     now,
				UpdatedAt:     now,
			}

			if err := u.identityRepo.Create(txCtx, identity); err != nil {
				return err
			}

			hash, err := password.Hash(input.Password)
			if err != nil {
				return err
			}

			credential := &authdomain.Credential{
				ID:             id.New(),
				IdentityID:     identity.ID,
				CredentialType: "password",
				PasswordHash:   hash,
				CreatedAt:      now,
				UpdatedAt:      now,
			}

			err = u.credentialRepo.Create(
				txCtx,
				credential,
			)
			if err != nil {
				return err
			}

			baseSlug := slug.FromEmail(
				input.Email,
			)

			uniqueSlug, err := u.slugService.GenerateUniqueSlug(
				txCtx,
				baseSlug,
			)

			if err != nil {
				return err
			}

			tenant := &tenantdomain.Tenant{
				ID:          id.New(),
				Slug:        uniqueSlug,
				DisplayName: input.Email,
				Status:      "active",
				CreatedAt:   now,
				UpdatedAt:   now,
			}

			err = u.tenantRepo.Create(
				txCtx,
				tenant,
			)
			if err != nil {
				return err
			}

			user := &identitydomain.User{
				ID:          id.New(),
				TenantID:    tenant.ID,
				IdentityID:  identity.ID,
				Username:    input.Email,
				DisplayName: input.Email,
				Status:      "active",
				CreatedAt:   now,
				UpdatedAt:   now,
			}

			err = u.userRepo.Create(
				txCtx,
				user,
			)
			if err != nil {
				return err
			}
			role, err := u.bootstrapService.CreateTenantOwnerRole(
				txCtx,
				tenant.ID,
			)

			if err != nil {
				return err
			}

			err = u.permissionBootstrapService.
				BootstrapTenantOwnerPermissions(
					txCtx,
					role.ID,
				)

			if err != nil {
				return err
			}

			err = u.userRoleRepo.AssignRole(
				txCtx,
				&authorizationdomain.UserRole{
					UserID:    user.ID,
					RoleID:    role.ID,
					CreatedAt: now,
				},
			)

			if err != nil {
				return err
			}

			return nil
		},
	)
}
