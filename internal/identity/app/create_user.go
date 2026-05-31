package app

import (
	"context"
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

	err := u.txManager.WithinTransaction(
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
		return nil, err
	}

	return created, nil
}
