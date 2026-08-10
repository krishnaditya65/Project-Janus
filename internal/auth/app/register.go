package app

import (
	"context"
	"fmt"
	"log/slog"
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
	now := time.Now().UTC()

	identity := &identitydomain.Identity{
		ID:            id.New(),
		PrimaryEmail:  input.Email,
		EmailVerified: false,
		Status:        "active",
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	// identityRepo.Create is a network call to identity-service, not part
	// of the local Postgres transaction below - it happens first, outside
	// txManager.WithinTransaction, so a failure here needs no compensation
	// of its own and the transaction below only ever runs against an
	// identity that already exists.
	if err := u.identityRepo.Create(ctx, identity); err != nil {
		return err
	}

	err := u.txManager.WithinTransaction(
		ctx,
		func(txCtx context.Context) error {
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

	if err != nil {
		// The identity was already persisted in identity-service (outside
		// this local transaction, which has since rolled back), so it must
		// be explicitly compensated for or it is orphaned: a row in
		// identity-service with no matching credential/tenant/user in this
		// service's database.
		if delErr := u.identityRepo.Delete(ctx, identity.ID); delErr != nil {
			slog.Error(
				"register: failed to compensate for orphaned identity after transaction failure",
				"identity_id", identity.ID,
				"tx_error", err,
				"delete_error", delErr,
			)
			return fmt.Errorf(
				"register: transaction failed (%w) and compensating identity delete also failed for identity %s: %w",
				err, identity.ID, delErr,
			)
		}

		return err
	}

	return nil
}
