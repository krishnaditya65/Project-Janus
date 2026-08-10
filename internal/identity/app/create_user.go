package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	authdomain "github.com/krishnaditya65/Project-Janus/internal/auth/domain"
	authorizationdomain "github.com/krishnaditya65/Project-Janus/internal/authorization/domain"
	identitydomain "github.com/krishnaditya65/Project-Janus/internal/identity/domain"

	"github.com/krishnaditya65/Project-Janus/internal/shared/id"
	"github.com/krishnaditya65/Project-Janus/internal/shared/password"
	"github.com/krishnaditya65/Project-Janus/internal/shared/tx"
)

type CreateUserInput struct {
	TenantID    string
	Email       string
	Password    string
	DisplayName string
	RoleName    string
}

type CreateUserUseCase struct {
	txManager tx.Manager

	identityRepo   identitydomain.Repository
	credentialRepo authdomain.Repository

	userRepo identitydomain.UserRepository

	roleRepo     authorizationdomain.RoleRepository
	userRoleRepo authorizationdomain.UserRoleRepository
}

func NewCreateUserUseCase(
	txManager tx.Manager,
	identityRepo identitydomain.Repository,
	credentialRepo authdomain.Repository,
	userRepo identitydomain.UserRepository,
	roleRepo authorizationdomain.RoleRepository,
	userRoleRepo authorizationdomain.UserRoleRepository,
) *CreateUserUseCase {

	return &CreateUserUseCase{
		txManager: txManager,

		identityRepo:   identityRepo,
		credentialRepo: credentialRepo,
		userRepo:       userRepo,

		roleRepo:     roleRepo,
		userRoleRepo: userRoleRepo,
	}
}

func (u *CreateUserUseCase) Execute(
	ctx context.Context,
	input CreateUserInput,
) (*identitydomain.User, error) {

	var created *identitydomain.User

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
		return nil, err
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

			if err := u.credentialRepo.Create(txCtx, credential); err != nil {
				return err
			}

			user := &identitydomain.User{
				ID:          id.New(),
				TenantID:    input.TenantID,
				IdentityID:  identity.ID,
				Username:    input.Email,
				DisplayName: input.DisplayName,
				Status:      "active",
				CreatedAt:   now,
				UpdatedAt:   now,
			}

			if err := u.userRepo.Create(txCtx, user); err != nil {
				return err
			}

			role, err := u.roleRepo.GetByTenantAndName(txCtx, input.TenantID, input.RoleName)
			if err != nil {
				return err
			}

			if err := u.userRoleRepo.AssignRole(txCtx, &authorizationdomain.UserRole{
				UserID:    user.ID,
				RoleID:    role.ID,
				CreatedAt: now,
			}); err != nil {
				return err
			}

			created = user
			return nil
		},
	)

	if err != nil {
		// The identity was already persisted (outside this local
		// transaction, which has since rolled back), so it must be
		// explicitly compensated for or it is orphaned: a row in
		// identity-service with no matching credential/user in this
		// service's database.
		if delErr := u.identityRepo.Delete(ctx, identity.ID); delErr != nil {
			slog.Error(
				"create_user: failed to compensate for orphaned identity after transaction failure",
				"identity_id", identity.ID,
				"tx_error", err,
				"delete_error", delErr,
			)
			return nil, fmt.Errorf(
				"create_user: transaction failed (%w) and compensating identity delete also failed for identity %s: %w",
				err, identity.ID, delErr,
			)
		}

		return nil, err
	}

	return created, nil
}
