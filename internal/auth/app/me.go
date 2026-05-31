package app

import (
	"context"

	authorizationdomain "github.com/krishnaditya65/Project-Janus/internal/authorization/domain"
	identitydomain "github.com/krishnaditya65/Project-Janus/internal/identity/domain"
	sessiondomain "github.com/krishnaditya65/Project-Janus/internal/session/domain"
)

type MeOutput struct {
	IdentityID string   `json:"identity_id"`
	UserID     string   `json:"user_id"`
	TenantID   string   `json:"tenant_id"`
	Email      string   `json:"email"`
	Roles      []string `json:"roles"`
}

type MeUseCase struct {
	sessionRepo  sessiondomain.Repository
	identityRepo identitydomain.Repository
	userRepo     identitydomain.UserRepository
	roleRepo     authorizationdomain.UserRoleRepository
}

func NewMeUseCase(
	sessionRepo sessiondomain.Repository,
	identityRepo identitydomain.Repository,
	userRepo identitydomain.UserRepository,
	roleRepo authorizationdomain.UserRoleRepository,
) *MeUseCase {

	return &MeUseCase{
		sessionRepo:  sessionRepo,
		identityRepo: identityRepo,
		userRepo:     userRepo,
		roleRepo:     roleRepo,
	}
}

func (u *MeUseCase) Execute(
	ctx context.Context,
	sessionID string,
) (*MeOutput, error) {

	session, err := u.sessionRepo.GetByID(
		ctx,
		sessionID,
	)
	if err != nil {
		return nil, err
	}

	identity, err := u.identityRepo.GetByID(
		ctx,
		session.IdentityID,
	)
	if err != nil {
		return nil, err
	}

	user, err := u.userRepo.GetByID(
		ctx,
		session.UserID,
	)
	if err != nil {
		return nil, err
	}

	roles, err := u.roleRepo.GetRolesForUser(
		ctx,
		user.ID,
	)
	if err != nil {
		return nil, err
	}

	return &MeOutput{
		IdentityID: identity.ID,
		UserID:     user.ID,
		TenantID:   user.TenantID,
		Email:      identity.PrimaryEmail,
		Roles:      roles,
	}, nil
}
