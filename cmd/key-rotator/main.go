package main

import (
	"context"
	"flag"
	"log/slog"
	"os"

	"github.com/krishnaditya65/Project-Janus/internal/platform/config"
	platformpostgres "github.com/krishnaditya65/Project-Janus/internal/platform/postgres"
	tokenapp "github.com/krishnaditya65/Project-Janus/internal/token/app"
	tokenpostgres "github.com/krishnaditya65/Project-Janus/internal/token/infra/postgres"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	alg := flag.String("alg", "ES256", "signing algorithm: ES256 or RS256")
	flag.Parse()

	cfg := config.Load()

	db, err := platformpostgres.New(cfg.DatabaseURL)
	if err != nil {
		slog.Error("postgres init failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	repo := tokenpostgres.NewRepository(db)
	ctx := context.Background()

	key, err := tokenapp.GenerateKey(*alg)
	if err != nil {
		slog.Error("key generation failed", "err", err)
		os.Exit(1)
	}

	if err := repo.DeactivateAll(ctx); err != nil {
		slog.Error("failed to deactivate existing keys", "err", err)
		os.Exit(1)
	}

	if err := repo.Create(ctx, key); err != nil {
		slog.Error("failed to insert new key", "err", err)
		os.Exit(1)
	}

	slog.Info("signing key rotated", "kid", key.ID, "alg", key.Algorithm)
}
