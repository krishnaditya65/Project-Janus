package app

import (
	"context"
	"encoding/json"
	"log/slog"

	natsgo "github.com/nats-io/nats.go"

	"github.com/krishnaditya65/auth-server/internal/audit/domain"
)

type Consumer struct {
	conn *natsgo.Conn
	repo domain.Repository
}

func NewConsumer(conn *natsgo.Conn, repo domain.Repository) *Consumer {
	return &Consumer{conn: conn, repo: repo}
}

// Subscribe registers the persistent handler. Returns the underlying
// subscription so the caller can drain on shutdown.
func (c *Consumer) Subscribe(ctx context.Context) (*natsgo.Subscription, error) {
	return c.conn.Subscribe(Subject, func(msg *natsgo.Msg) {
		e := &domain.Event{}
		if err := json.Unmarshal(msg.Data, e); err != nil {
			slog.Warn("audit consume: bad message", "err", err)
			return
		}
		if err := c.repo.Insert(ctx, e); err != nil {
			slog.Error("audit consume: insert failed", "err", err, "event_type", e.EventType)
		}
	})
}
