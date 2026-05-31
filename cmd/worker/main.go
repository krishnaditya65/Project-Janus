// Worker binary: long-running background jobs.
//
// Responsibilities:
//  1. Subscribe to NATS subject "audit.events" and persist to audit_events.
//  2. Periodically delete sessions where expires_at < now()-retention or
//     revoked_at < now()-retention.
//
// Runs forever; SIGINT/SIGTERM for clean shutdown.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	auditapp "github.com/krishnaditya65/Project-Janus/internal/audit/app"
	auditpostgres "github.com/krishnaditya65/Project-Janus/internal/audit/infra/postgres"
	"github.com/krishnaditya65/Project-Janus/internal/platform/config"
	"github.com/krishnaditya65/Project-Janus/internal/platform/nats"
	platformpostgres "github.com/krishnaditya65/Project-Janus/internal/platform/postgres"
	sessionpostgres "github.com/krishnaditya65/Project-Janus/internal/session/infra/postgres"
)

const (
	sessionCleanupInterval = 5 * time.Minute
	sessionRetention       = 30 * 24 * time.Hour
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg := config.Load()

	db, err := platformpostgres.New(cfg.DatabaseURL)
	if err != nil {
		slog.Error("postgres init failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	bus, err := nats.New(cfg.NATSURL)
	if err != nil {
		slog.Error("nats init failed", "err", err)
		os.Exit(1)
	}
	defer bus.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	auditRepo := auditpostgres.NewRepository(db)
	consumer := auditapp.NewConsumer(bus, auditRepo)
	sub, err := consumer.Subscribe(ctx)
	if err != nil {
		slog.Error("audit subscribe failed", "err", err)
		os.Exit(1)
	}
	defer sub.Unsubscribe()
	slog.Info("audit consumer ready", "subject", auditapp.Subject)

	sessionRepo := sessionpostgres.NewRepository(db)
	go runSessionCleanup(ctx, sessionRepo)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	slog.Info("shutting down", "signal", sig.String())
	cancel()
}

func runSessionCleanup(ctx context.Context, repo *sessionpostgres.Repository) {
	t := time.NewTicker(sessionCleanupInterval)
	defer t.Stop()

	cleanup := func() {
		cutoff := time.Now().UTC().Add(-sessionRetention)
		n, err := repo.DeleteExpiredOrRevoked(ctx, cutoff)
		if err != nil {
			slog.Error("session cleanup failed", "err", err)
			return
		}
		if n > 0 {
			slog.Info("session cleanup", "deleted", n, "cutoff", cutoff)
		}
	}

	cleanup()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cleanup()
		}
	}
}
