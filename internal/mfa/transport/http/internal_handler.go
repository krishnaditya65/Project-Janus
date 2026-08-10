package http

import (
	mfaapp "github.com/krishnaditya65/Project-Janus/internal/mfa/app"
	mfadomain "github.com/krishnaditya65/Project-Janus/internal/mfa/domain"
)

// InternalHandler serves mfa-service's internal, network-only API for
// mfadomain.Repository (factor CRUD) and the Redis-backed ChallengeStore
// (Store/Consume). It is deliberately separate from Handler (which serves
// principal-authenticated MFA routes like enroll/verify/list/complete): these
// routes back the httpclient adapter used by auth's LoginUseCase and must be
// reachable without a session principal, the same way identity-service's
// IdentityHandler backs identity's httpclient adapter.
type InternalHandler struct {
	factorRepo     mfadomain.Repository
	challengeStore *mfaapp.ChallengeStore
}

func NewInternalHandler(
	factorRepo mfadomain.Repository,
	challengeStore *mfaapp.ChallengeStore,
) *InternalHandler {

	return &InternalHandler{
		factorRepo:     factorRepo,
		challengeStore: challengeStore,
	}
}
