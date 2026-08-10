package http

import identityapp "github.com/krishnaditya65/Project-Janus/internal/identity/app"

// IdentityHandler serves identity-service's internal, network-only API for
// identitydomain.Repository (Create/GetByEmail/GetByID on Identity). It is
// deliberately separate from Handler (which serves tenant-scoped User
// management behind session auth): these routes back the httpclient adapter
// used by auth/mfa/oauth/webauthn and must be reachable pre-authentication
// (e.g. during login, before a principal exists).
type IdentityHandler struct {
	getByEmailUseCase *identityapp.GetIdentityByEmailUseCase
	getByIDUseCase    *identityapp.GetIdentityByIDUseCase
	persistUseCase    *identityapp.PersistIdentityUseCase
	deleteUseCase     *identityapp.DeleteIdentityUseCase
}

func NewIdentityHandler(
	getByEmailUseCase *identityapp.GetIdentityByEmailUseCase,
	getByIDUseCase *identityapp.GetIdentityByIDUseCase,
	persistUseCase *identityapp.PersistIdentityUseCase,
	deleteUseCase *identityapp.DeleteIdentityUseCase,
) *IdentityHandler {

	return &IdentityHandler{
		getByEmailUseCase: getByEmailUseCase,
		getByIDUseCase:    getByIDUseCase,
		persistUseCase:    persistUseCase,
		deleteUseCase:     deleteUseCase,
	}
}
