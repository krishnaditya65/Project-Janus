// identity-service: standalone binary owning the identities table.
//
// It is the only binary that talks to Postgres for identitydomain.Repository
// (Create/GetByEmail/GetByID on Identity) directly. Every other service
// (iam-server today) reaches it over HTTP via
// internal/identity/infra/httpclient, so the wiring here mirrors exactly
// what cmd/iam-server/main.go used to construct for identity before the
// split: the same identitypostgres.Repository, the same app-layer use
// cases, fronted by a small internal-only HTTP API.
//
// Note: the database itself stays shared across iam-server and
// identity-service (see project decision) - this split is a network-API
// boundary, not a data-ownership split. Both binaries load DATABASE_URL
// from the same config and open their own connection pool against it.
package main

import (
	"log/slog"
	"net/http"
	"os"

	identityapp "github.com/krishnaditya65/Project-Janus/internal/identity/app"
	identitypostgres "github.com/krishnaditya65/Project-Janus/internal/identity/infra/postgres"
	identityhttp "github.com/krishnaditya65/Project-Janus/internal/identity/transport/http"

	"github.com/krishnaditya65/Project-Janus/internal/platform/config"
	"github.com/krishnaditya65/Project-Janus/internal/platform/httpserver"
	"github.com/krishnaditya65/Project-Janus/internal/platform/metrics"
	platformpostgres "github.com/krishnaditya65/Project-Janus/internal/platform/postgres"

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

	slog.Info("infrastructure connected", "postgres", cfg.DatabaseURL != "", "env", cfg.AppEnv)

	// repository
	identityRepo := identitypostgres.NewRepository(db)

	// use cases
	getByEmailUseCase := identityapp.NewGetIdentityByEmailUseCase(identityRepo)
	getByIDUseCase := identityapp.NewGetIdentityByIDUseCase(identityRepo)
	persistUseCase := identityapp.NewPersistIdentityUseCase(identityRepo)
	deleteUseCase := identityapp.NewDeleteIdentityUseCase(identityRepo)

	// handler
	identityHandler := identityhttp.NewIdentityHandler(
		getByEmailUseCase,
		getByIDUseCase,
		persistUseCase,
		deleteUseCase,
	)

	server := httpserver.New(cfg.IdentityHTTPPort)
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

	r.Get("/internal/identities/by-email", identityHandler.GetIdentityByEmail)
	r.Get("/internal/identities/{id}", identityHandler.GetIdentityByID)
	r.Post("/internal/identities", identityHandler.CreateIdentity)
	r.Delete("/internal/identities/{id}", identityHandler.DeleteIdentity)

	slog.Info("starting identity-service", "port", cfg.IdentityHTTPPort, "env", cfg.AppEnv)

	if err := server.Start(); err != nil {
		slog.Error("server failed", "err", err)
		os.Exit(1)
	}
}
