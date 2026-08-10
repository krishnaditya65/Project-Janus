package middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	authdomain "github.com/krishnaditya65/Project-Janus/internal/authorization/domain"
	identitydomain "github.com/krishnaditya65/Project-Janus/internal/identity/domain"
	sessiondomain "github.com/krishnaditya65/Project-Janus/internal/session/domain"
	authctx "github.com/krishnaditya65/Project-Janus/internal/shared/context"
	"github.com/krishnaditya65/Project-Janus/internal/shared/principal"
	tokenapp "github.com/krishnaditya65/Project-Janus/internal/token/app"
)

type AuthenticationMiddleware struct {
	sessionRepo        sessiondomain.Repository
	identityRepo       identitydomain.Repository
	userRoleRepo       authdomain.UserRoleRepository
	rolePermissionRepo authdomain.RolePermissionRepository
	jwtService         *tokenapp.JWTService
	cache              *PrincipalCache
}

func NewAuthenticationMiddleware(
	sessionRepo sessiondomain.Repository,
	identityRepo identitydomain.Repository,
	userRoleRepo authdomain.UserRoleRepository,
	rolePermissionRepo authdomain.RolePermissionRepository,
	jwtService *tokenapp.JWTService,
	cache *PrincipalCache,
) *AuthenticationMiddleware {
	return &AuthenticationMiddleware{
		sessionRepo:        sessionRepo,
		identityRepo:       identityRepo,
		userRoleRepo:       userRoleRepo,
		rolePermissionRepo: rolePermissionRepo,
		jwtService:         jwtService,
		cache:              cache,
	}
}

func (m *AuthenticationMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := m.fromBearer(r); p != nil {
			ctx := authctx.WithPrincipal(r.Context(), p)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		if p := m.fromSessionHeader(r); p != nil {
			ctx := authctx.WithPrincipal(r.Context(), p)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func (m *AuthenticationMiddleware) fromBearer(r *http.Request) *principal.Principal {
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		return nil
	}
	tokenStr := strings.TrimPrefix(authz, "Bearer ")
	if tokenStr == "" {
		return nil
	}

	claims, err := m.jwtService.Verify(r.Context(), tokenStr)
	if err != nil {
		slog.Warn("jwt verify failed", "err", err)
		return nil
	}

	return &principal.Principal{
		SessionID:   claims.SessionID,
		IdentityID:  claims.Subject,
		TenantID:    claims.TenantID,
		UserID:      claims.UserID,
		Email:       claims.Email,
		Roles:       claims.Roles,
		Permissions: claims.Permissions,
	}
}

func (m *AuthenticationMiddleware) fromSessionHeader(r *http.Request) *principal.Principal {
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		return nil
	}

	if p, ok := m.cache.Get(r.Context(), sessionID); ok {
		return p
	}

	session, err := m.sessionRepo.GetByID(r.Context(), sessionID)
	if err != nil {
		slog.Warn("session lookup failed", "session_id", sessionID, "path", r.URL.Path)
		return nil
	}

	if session.RevokedAt != nil {
		slog.Warn("rejected revoked session", "session_id", sessionID)
		return nil
	}

	if time.Now().UTC().After(session.ExpiresAt) {
		slog.Warn("rejected expired session", "session_id", sessionID)
		return nil
	}

	identity, err := m.identityRepo.GetByID(r.Context(), session.IdentityID)
	if err != nil {
		slog.Error("identity lookup failed", "identity_id", session.IdentityID, "err", err)
		return nil
	}

	roles, err := m.userRoleRepo.GetRolesForUser(r.Context(), session.UserID)
	if err != nil {
		slog.Error("role lookup failed", "user_id", session.UserID, "err", err)
		return nil
	}

	permissions, err := m.rolePermissionRepo.GetPermissionsForUser(r.Context(), session.UserID)
	if err != nil {
		slog.Error("permission lookup failed", "user_id", session.UserID, "err", err)
		return nil
	}

	authPrincipal := &principal.Principal{
		SessionID:   session.ID,
		IdentityID:  session.IdentityID,
		TenantID:    session.TenantID,
		UserID:      session.UserID,
		Email:       identity.PrimaryEmail,
		Roles:       roles,
		Permissions: permissions,
	}
	m.cache.Put(r.Context(), authPrincipal)
	return authPrincipal
}
