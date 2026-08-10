// mfa-service: standalone binary that owns internal/mfa (TOTP factors, MFA
// challenges) and internal/webauthn (WebAuthn/passkey credentials), split
// out of cmd/iam-server the same way cmd/identity-service split identity
// out earlier.
//
// It serves two kinds of routes:
//   - principal-authenticated routes (mfa enroll/verify/list/complete,
//     webauthn register/login/list) that used to live on iam-server's
//     router directly - these need the same AuthenticationMiddleware
//     iam-server uses, reconstructed here from the same shared Postgres
//     tables and Redis principal cache, since JWTs are signed with the
//     same shared signing-key table either binary can verify.
//   - internal-only routes (factor CRUD, challenge store/consume) that back
//     internal/mfa/infra/httpclient, used by auth's LoginUseCase now that
//     it can no longer hold a Postgres-backed mfadomain.Repository or a
//     concrete *mfaapp.ChallengeStore in-process.
//
// Postgres and Redis both stay shared with iam-server (see project
// decision on the identity split) - this is a network-API boundary, not a
// data-ownership split. Both binaries load DATABASE_URL/REDIS_ADDR from the
// same config and open their own connections against them.
package main

import (
	"log/slog"
	"net/http"
	"os"

	authmiddleware "github.com/krishnaditya65/Project-Janus/internal/auth/middleware"
	authorizationpostgres "github.com/krishnaditya65/Project-Janus/internal/authorization/infra/postgres"

	identityhttpclient "github.com/krishnaditya65/Project-Janus/internal/identity/infra/httpclient"
	postgresuser "github.com/krishnaditya65/Project-Janus/internal/identity/infra/postgresuser"

	mfaapp "github.com/krishnaditya65/Project-Janus/internal/mfa/app"
	mfapostgres "github.com/krishnaditya65/Project-Janus/internal/mfa/infra/postgres"
	mfahttp "github.com/krishnaditya65/Project-Janus/internal/mfa/transport/http"

	waapp "github.com/krishnaditya65/Project-Janus/internal/webauthn/app"
	wapostgres "github.com/krishnaditya65/Project-Janus/internal/webauthn/infra/postgres"
	wahttp "github.com/krishnaditya65/Project-Janus/internal/webauthn/transport/http"

	sessionpostgres "github.com/krishnaditya65/Project-Janus/internal/session/infra/postgres"

	"github.com/krishnaditya65/Project-Janus/internal/platform/config"
	"github.com/krishnaditya65/Project-Janus/internal/platform/httpserver"
	"github.com/krishnaditya65/Project-Janus/internal/platform/metrics"
	platformpostgres "github.com/krishnaditya65/Project-Janus/internal/platform/postgres"
	"github.com/krishnaditya65/Project-Janus/internal/platform/redis"
	tokenapp "github.com/krishnaditya65/Project-Janus/internal/token/app"
	tokenpostgres "github.com/krishnaditya65/Project-Janus/internal/token/infra/postgres"

	"github.com/go-chi/chi/v5"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg := config.Load()

	db, err := platformpostgres.New(cfg.DatabaseURL)
	if err != nil {
		slog.Error("postgres init failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	cache, err := redis.New(cfg.RedisAddr)
	if err != nil {
		slog.Error("redis init failed", "err", err)
		os.Exit(1)
	}
	defer cache.Close()

	slog.Info("infrastructure connected", "postgres", cfg.DatabaseURL != "", "env", cfg.AppEnv)

	// identityRepo talks to identity-service over HTTP, exactly as
	// iam-server's does - mfa-service needs identity lookups for TOTP
	// enrollment (email for the otpauth QR code), MFA completion, and
	// webauthn registration/login.
	identityRepo := identityhttpclient.NewRepository(cfg.IdentityServiceURL)

	sessionRepo := sessionpostgres.NewRepository(db)
	userRepo := postgresuser.NewRepository(db)
	userRoleRepo := authorizationpostgres.NewUserRoleRepository(db)
	rolePermissionRepo := authorizationpostgres.NewRolePermissionRepository(db)
	signingKeyRepo := tokenpostgres.NewRepository(db)

	jwtService := tokenapp.NewJWTService(signingKeyRepo, cfg.JWTIssuer)
	principalCache := authmiddleware.NewPrincipalCache(cache)

	// mfa
	mfaRepo := mfapostgres.NewRepository(db)
	mfaChallengeStore := mfaapp.NewChallengeStore(cache)
	totpService := mfaapp.NewTOTPService(mfaRepo, cfg.JWTIssuer)
	mfaCompleteUseCase := mfaapp.NewCompleteUseCase(
		mfaChallengeStore,
		totpService,
		sessionRepo,
		identityRepo,
		userRoleRepo,
		rolePermissionRepo,
		jwtService,
	)
	mfaHandler := mfahttp.NewHandler(totpService, mfaCompleteUseCase)
	mfaInternalHandler := mfahttp.NewInternalHandler(mfaRepo, mfaChallengeStore)

	// webauthn
	waCredRepo := wapostgres.NewRepository(db)
	waSessionStore := waapp.NewSessionStore(cache)
	waService, err := waapp.NewService(
		cfg.WebAuthnName, cfg.WebAuthnRPID, []string{cfg.WebAuthnOrigin},
		waCredRepo, identityRepo, waSessionStore,
	)
	if err != nil {
		slog.Error("webauthn init failed", "err", err)
		os.Exit(1)
	}
	waLoginUseCase := waapp.NewLoginUseCase(
		waService, sessionRepo, identityRepo, userRepo, userRoleRepo, rolePermissionRepo, jwtService,
	)
	waHandler := wahttp.NewHandler(waService, waLoginUseCase)

	// authMiddleware backs the principal-authenticated routes below - same
	// construction iam-server uses for its own routes, against the same
	// shared session/authorization tables and signing keys.
	authMiddleware := authmiddleware.NewAuthenticationMiddleware(
		sessionRepo,
		identityRepo,
		userRoleRepo,
		rolePermissionRepo,
		jwtService,
		principalCache,
	)

	server := httpserver.New(cfg.MFAHTTPPort)
	r := server.Router()

	r.Use(httpserver.RequestLogger)
	r.Use(metrics.Middleware(func(req *http.Request) string {
		if rc := chi.RouteContext(req.Context()); rc != nil {
			if p := rc.RoutePattern(); p != "" {
				return p
			}
		}
		return req.URL.Path
	}))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	r.Mount("/metrics", metrics.Handler())

	// public routes (no session principal required)
	r.Post("/mfa/complete", mfaHandler.Complete)
	r.Post("/webauthn/login/begin", waHandler.LoginBegin)
	r.Post("/webauthn/login/complete", waHandler.LoginComplete)

	// internal-only routes backing internal/mfa/infra/httpclient - trusted
	// network boundary, same convention as identity-service's
	// /internal/identities/* routes (no auth middleware).
	r.Post("/internal/mfa/factors", mfaInternalHandler.CreateFactor)
	r.Get("/internal/mfa/factors/by-identity", mfaInternalHandler.GetFactorsByIdentity)
	r.Get("/internal/mfa/factors/verified", mfaInternalHandler.GetVerifiedFactorsByIdentity)
	r.Get("/internal/mfa/factors/{id}", mfaInternalHandler.GetFactorByID)
	r.Post("/internal/mfa/factors/{id}/verify", mfaInternalHandler.MarkFactorVerified)
	r.Delete("/internal/mfa/factors/{id}", mfaInternalHandler.DeleteFactor)
	r.Post("/internal/mfa/challenges", mfaInternalHandler.StoreChallenge)
	r.Post("/internal/mfa/challenges/consume", mfaInternalHandler.ConsumeChallenge)

	// principal-authenticated routes
	withAuth := func(next http.Handler) http.Handler {
		return authMiddleware.Authenticate(next)
	}

	r.With(withAuth).Post("/mfa/enroll/totp", mfaHandler.EnrollTOTP)
	r.With(withAuth).Post("/mfa/enroll/verify", mfaHandler.VerifyEnrollment)
	r.With(withAuth).Get("/mfa/factors", mfaHandler.List)

	r.With(withAuth).Post("/webauthn/register/begin", waHandler.RegisterBegin)
	r.With(withAuth).Post("/webauthn/register/complete", waHandler.RegisterComplete)
	r.With(withAuth).Get("/webauthn/credentials", waHandler.List)

	slog.Info("starting mfa-service", "port", cfg.MFAHTTPPort, "env", cfg.AppEnv)

	if err := server.Start(); err != nil {
		slog.Error("server failed", "err", err)
		os.Exit(1)
	}
}
