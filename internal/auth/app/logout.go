package app

import (
	"context"

	sessiondomain "github.com/krishnaditya65/auth-server/internal/session/domain"
	sharederrors "github.com/krishnaditya65/auth-server/internal/shared/errors"
)

type LogoutInput struct {
	SessionID string
}

// PrincipalInvalidator removes the cached principal so a revoked session can
// no longer authenticate via the cache. Kept as a tiny interface so this
// package does not depend on the middleware package.
type PrincipalInvalidator interface {
	Delete(ctx context.Context, sessionID string)
}

type LogoutUseCase struct {
	sessionRepo sessiondomain.Repository
	invalidator PrincipalInvalidator
}

func NewLogoutUseCase(sessionRepo sessiondomain.Repository, invalidator PrincipalInvalidator) *LogoutUseCase {
	return &LogoutUseCase{sessionRepo: sessionRepo, invalidator: invalidator}
}

func (u *LogoutUseCase) Execute(ctx context.Context, input LogoutInput) error {
	session, err := u.sessionRepo.GetByID(ctx, input.SessionID)
	if err != nil {
		return sharederrors.ErrNotFound
	}

	if session.RevokedAt != nil {
		if u.invalidator != nil {
			u.invalidator.Delete(ctx, input.SessionID)
		}
		return nil
	}

	if err := u.sessionRepo.Revoke(ctx, session.ID); err != nil {
		return err
	}
	if u.invalidator != nil {
		u.invalidator.Delete(ctx, input.SessionID)
	}
	return nil
}
