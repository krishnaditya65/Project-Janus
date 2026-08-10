package app

import (
	"context"

	identitydomain "github.com/krishnaditya65/Project-Janus/internal/identity/domain"
)

// PersistIdentityUseCase persists an already-constructed Identity exactly as
// given: it does not generate an ID, status, or timestamps the way
// CreateIdentityUseCase does from a bare email. It exists because auth's
// RegisterUseCase and identity's own CreateUserUseCase already build a
// fully-formed *identitydomain.Identity (ID, status, timestamps included)
// before calling Repository.Create - identity-service's internal HTTP API
// must persist that Identity as-is (same contract as
// identitypostgres.Repository.Create) rather than mint a new one, or the
// caller's in-memory Identity (and anything derived from its ID, e.g.
// credentials/sessions) would disagree with what was actually stored.
type PersistIdentityUseCase struct {
	repo identitydomain.Repository
}

func NewPersistIdentityUseCase(
	repo identitydomain.Repository,
) *PersistIdentityUseCase {

	return &PersistIdentityUseCase{
		repo: repo,
	}
}

func (u *PersistIdentityUseCase) Execute(
	ctx context.Context,
	identity *identitydomain.Identity,
) error {

	return u.repo.Create(ctx, identity)
}
