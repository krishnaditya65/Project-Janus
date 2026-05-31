package main

import (
	"log/slog"
	"net/http"
	"os"

	authapp "github.com/krishnaditya65/Project-Janus/internal/auth/app"
	authpostgres "github.com/krishnaditya65/Project-Janus/internal/auth/infra/postgres"
	authmiddleware "github.com/krishnaditya65/Project-Janus/internal/auth/middleware"
	authhttp "github.com/krishnaditya65/Project-Janus/internal/auth/transport/http"
	authorizationapp "github.com/krishnaditya65/Project-Janus/internal/authorization/app"
	authorizationpostgres "github.com/krishnaditya65/Project-Janus/internal/authorization/infra/postgres"
	authorizationmiddleware "github.com/krishnaditya65/Project-Janus/internal/authorization/middleware"
	authorizationhttp "github.com/krishnaditya65/Project-Janus/internal/authorization/transport/http"

	identitypostgres "github.com/krishnaditya65/Project-Janus/internal/identity/infra/postgres"
	tenantapp "github.com/krishnaditya65/Project-Janus/internal/tenant/app"
	tenantpostgres "github.com/krishnaditya65/Project-Janus/internal/tenant/infra/postgres"

	postgresuser "github.com/krishnaditya65/Project-Janus/internal/identity/infra/postgresuser"
	sessionpostgres "github.com/krishnaditya65/Project-Janus/internal/session/infra/postgres"

	identityapp "github.com/krishnaditya65/Project-Janus/internal/identity/app"
	identityhttp "github.com/krishnaditya65/Project-Janus/internal/identity/transport/http"

	"github.com/krishnaditya65/Project-Janus/internal/platform/config"
	"github.com/krishnaditya65/Project-Janus/internal/platform/httpserver"
	"github.com/krishnaditya65/Project-Janus/internal/platform/nats"
	platformpostgres "github.com/krishnaditya65/Project-Janus/internal/platform/postgres"
	pgtx "github.com/krishnaditya65/Project-Janus/internal/platform/postgres/tx"
	"github.com/krishnaditya65/Project-Janus/internal/platform/redis"
	tokenapp "github.com/krishnaditya65/Project-Janus/internal/token/app"
	tokenpostgres "github.com/krishnaditya65/Project-Janus/internal/token/infra/postgres"
	tokenhttp "github.com/krishnaditya65/Project-Janus/internal/token/transport/http"

	oauthapp "github.com/krishnaditya65/Project-Janus/internal/oauth/app"
	oauthpostgres "github.com/krishnaditya65/Project-Janus/internal/oauth/infra/postgres"
	oauthredis "github.com/krishnaditya65/Project-Janus/internal/oauth/infra/redis"
	oauthhttp "github.com/krishnaditya65/Project-Janus/internal/oauth/transport/http"

	oidcapp "github.com/krishnaditya65/Project-Janus/internal/oidc/app"
	oidchttp "github.com/krishnaditya65/Project-Janus/internal/oidc/transport/http"

	mfaapp "github.com/krishnaditya65/Project-Janus/internal/mfa/app"
	mfapostgres "github.com/krishnaditya65/Project-Janus/internal/mfa/infra/postgres"
	mfahttp "github.com/krishnaditya65/Project-Janus/internal/mfa/transport/http"

	waapp "github.com/krishnaditya65/Project-Janus/internal/webauthn/app"
	wapostgres "github.com/krishnaditya65/Project-Janus/internal/webauthn/infra/postgres"
	wahttp "github.com/krishnaditya65/Project-Janus/internal/webauthn/transport/http"

	auditapp "github.com/krishnaditya65/Project-Janus/internal/audit/app"
	"github.com/krishnaditya65/Project-Janus/internal/platform/metrics"
	tenanthttp "github.com/krishnaditya65/Project-Janus/internal/tenant/transport/http"

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

	msgBus, err := nats.New(cfg.NATSURL)
	if err != nil {
		slog.Error("nats init failed", "err", err)
		os.Exit(1)
	}
	defer msgBus.Close()

	slog.Info("infrastructure connected", "postgres", cfg.DatabaseURL != "", "env", cfg.AppEnv)

	txManager := pgtx.NewManager(db)

	// repositories
	identityRepo := identitypostgres.NewRepository(db)
	credentialRepo := authpostgres.NewRepository(db)
	tenantRepo := tenantpostgres.NewRepository(db)
	userRepo := postgresuser.NewRepository(db)
	sessionRepo := sessionpostgres.NewRepository(db)
	permissionRepo := authorizationpostgres.NewPermissionRepository(db)
	rolePermissionRepo := authorizationpostgres.NewRolePermissionRepository(db)
	roleRepo := authorizationpostgres.NewRoleRepository(db)
	userRoleRepo := authorizationpostgres.NewUserRoleRepository(db)
	signingKeyRepo := tokenpostgres.NewRepository(db)
	oauthClientRepo := oauthpostgres.NewClientRepository(db)
	oauthCodeStore := oauthredis.NewCodeStore(cache)
	mfaRepo := mfapostgres.NewRepository(db)
	mfaChallengeStore := mfaapp.NewChallengeStore(cache)
	tenantPolicyRepo := tenantpostgres.NewPolicyRepository(db)

	// services
	jwtService := tokenapp.NewJWTService(signingKeyRepo, cfg.JWTIssuer)
	totpService := mfaapp.NewTOTPService(mfaRepo, cfg.JWTIssuer)
	policyEnforcer := tenantapp.NewPolicyEnforcer(tenantPolicyRepo)
	principalCache := authmiddleware.NewPrincipalCache(cache)
	auditPublisher := auditapp.NewPublisher(msgBus)
	_ = auditPublisher // emit calls added in handlers/use cases in follow-up; keep for now
	slugService := tenantapp.NewSlugService(tenantRepo)
	bootstrapService := authorizationapp.NewBootstrapService(roleRepo)
	permissionBootstrapService := authorizationapp.NewPermissionBootstrapService(
		permissionRepo,
		rolePermissionRepo,
	)

	// use cases
	registerUseCase := authapp.NewRegisterUseCase(
		txManager,
		identityRepo,
		credentialRepo,
		tenantRepo,
		userRepo,
		slugService,
		userRoleRepo,
		bootstrapService,
		permissionBootstrapService,
	)

	loginUseCase := authapp.NewLoginUseCase(
		identityRepo,
		credentialRepo,
		userRepo,
		userRoleRepo,
		rolePermissionRepo,
		sessionRepo,
		jwtService,
		mfaRepo,
		mfaChallengeStore,
		policyEnforcer,
	)

	mfaCompleteUseCase := mfaapp.NewCompleteUseCase(
		mfaChallengeStore,
		totpService,
		sessionRepo,
		identityRepo,
		userRoleRepo,
		rolePermissionRepo,
		jwtService,
	)

	refreshUseCase := authapp.NewRefreshUseCase(
		sessionRepo,
		identityRepo,
		userRoleRepo,
		rolePermissionRepo,
		jwtService,
		principalCache,
	)

	logoutUseCase := authapp.NewLogoutUseCase(sessionRepo, principalCache)

	identityGetUserUseCase := identityapp.NewGetUserUseCase(userRepo)
	listUsersUseCase := identityapp.NewListUsersUseCase(userRepo)
	createUserUseCase := identityapp.NewCreateUserUseCase(
		txManager,
		identityRepo,
		credentialRepo,
		userRepo,
		roleRepo,
		userRoleRepo,
	)

	createRoleUseCase := authorizationapp.NewCreateRoleUseCase(roleRepo)
	listRolesUseCase := authorizationapp.NewListRolesUseCase(roleRepo)
	assignPermissionUseCase := authorizationapp.NewAssignPermissionToRoleUseCase(
		roleRepo,
		permissionRepo,
		rolePermissionRepo,
	)
	listRolePermissionsUseCase := authorizationapp.NewListRolePermissionsUseCase(
		roleRepo,
		rolePermissionRepo,
	)

	// handlers
	authHandler := authhttp.NewHandler(
		registerUseCase,
		loginUseCase,
		refreshUseCase,
		logoutUseCase,
	)

	identityHandler := identityhttp.NewHandler(
		identityGetUserUseCase,
		listUsersUseCase,
		createUserUseCase,
	)

	authorizationHandler := authorizationhttp.NewHandler(
		createRoleUseCase,
		listRolesUseCase,
		assignPermissionUseCase,
		listRolePermissionsUseCase,
	)

	// middleware
	authMiddleware := authmiddleware.NewAuthenticationMiddleware(
		sessionRepo,
		identityRepo,
		userRoleRepo,
		rolePermissionRepo,
		jwtService,
		principalCache,
	)

	policyHandler := tenanthttp.NewPolicyHandler(policyEnforcer, tenantPolicyRepo)

	jwksHandler := tokenhttp.NewHandler(signingKeyRepo)

	idTokenService := oidcapp.NewIDTokenService(jwtService)
	oidcHandler := oidchttp.NewHandler(cfg.JWTIssuer)
	userInfoHandler := oidchttp.NewUserInfoHandler(identityRepo)

	authorizeUseCase := oauthapp.NewAuthorizeUseCase(oauthClientRepo, oauthCodeStore)
	oauthTokenUseCase := oauthapp.NewTokenUseCase(
		oauthClientRepo,
		oauthCodeStore,
		sessionRepo,
		identityRepo,
		userRoleRepo,
		rolePermissionRepo,
		jwtService,
		idTokenService,
	)
	oauthHandler := oauthhttp.NewHandler(authorizeUseCase, oauthTokenUseCase)

	mfaHandler := mfahttp.NewHandler(totpService, mfaCompleteUseCase)

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

	server := httpserver.New(cfg.HTTPPort)
	r := server.Router()

	r.Use(httpserver.CORS)
	r.Use(httpserver.RequestLogger)
	r.Use(metrics.Middleware(func(req *http.Request) string {
		// chi exposes the matched route pattern via RouteContext
		if rc := chi.RouteContext(req.Context()); rc != nil {
			if p := rc.RoutePattern(); p != "" {
				return p
			}
		}
		return req.URL.Path
	}))

	// public routes
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	r.Post("/register", authHandler.Register)
	r.Post("/login", authHandler.Login)
	r.Post("/refresh", authHandler.Refresh)
	r.Get("/.well-known/jwks.json", jwksHandler.JWKS)
	r.Get("/.well-known/openid-configuration", oidcHandler.Discovery)
	r.Mount("/metrics", metrics.Handler())
	r.Post("/oauth/token", oauthHandler.Token)
	r.Post("/mfa/complete", mfaHandler.Complete)
	r.Post("/webauthn/login/begin", waHandler.LoginBegin)
	r.Post("/webauthn/login/complete", waHandler.LoginComplete)

	// authenticated routes
	withAuth := func(next http.Handler) http.Handler {
		return authMiddleware.Authenticate(next)
	}
	withPerm := func(p string) func(http.Handler) http.Handler {
		return authorizationmiddleware.RequirePermission(p)
	}

	r.With(withAuth).Get("/me", authHandler.Me)
	r.With(withAuth).Post("/logout", authHandler.Logout)
	r.With(withAuth).Get("/oauth/authorize", oauthHandler.Authorize)
	r.With(withAuth).Get("/oauth/userinfo", userInfoHandler.UserInfo)

	r.With(withAuth).Post("/mfa/enroll/totp", mfaHandler.EnrollTOTP)
	r.With(withAuth).Post("/mfa/enroll/verify", mfaHandler.VerifyEnrollment)
	r.With(withAuth).Get("/mfa/factors", mfaHandler.List)

	r.With(withAuth).Post("/webauthn/register/begin", waHandler.RegisterBegin)
	r.With(withAuth).Post("/webauthn/register/complete", waHandler.RegisterComplete)
	r.With(withAuth).Get("/webauthn/credentials", waHandler.List)

	r.With(withAuth).Get("/tenant/policy", policyHandler.Get)
	r.With(withAuth, withPerm("tenant:update")).Put("/tenant/policy", policyHandler.Put)

	r.With(withAuth, withPerm("users:read")).Get("/users", identityHandler.ListUsers)
	r.With(withAuth, withPerm("users:read")).Get("/users/{userID}", identityHandler.GetUser)
	r.With(withAuth, withPerm("users:create")).Post("/users", identityHandler.CreateUser)

	r.With(withAuth, withPerm("roles:create")).Post("/roles", authorizationHandler.CreateRole)
	r.With(withAuth, withPerm("roles:read")).Get("/roles", authorizationHandler.ListRoles)
	r.With(withAuth, withPerm("roles:update")).Post("/roles/{roleID}/permissions", authorizationHandler.AssignPermission)
	r.With(withAuth, withPerm("roles:read")).Get("/roles/{roleID}/permissions", authorizationHandler.ListRolePermissions)

	slog.Info("starting auth server", "port", cfg.HTTPPort, "env", cfg.AppEnv)

	if err := server.Start(); err != nil {
		slog.Error("server failed", "err", err)
		os.Exit(1)
	}
}
