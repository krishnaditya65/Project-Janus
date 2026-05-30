// Publisher fires audit events to NATS subject "audit.events".
// Non-blocking: failure to publish is logged and dropped; we never want
// audit instrumentation to slow down the auth path.
package app

import (
	"encoding/json"
	"log/slog"
	"time"

	natsgo "github.com/nats-io/nats.go"

	"github.com/krishnaditya65/auth-server/internal/audit/domain"
	"github.com/krishnaditya65/auth-server/internal/shared/id"
)

const Subject = "audit.events"

type Publisher struct {
	conn *natsgo.Conn
}

func NewPublisher(conn *natsgo.Conn) *Publisher {
	return &Publisher{conn: conn}
}

// Emit fills in id + timestamp and publishes. Best-effort.
func (p *Publisher) Emit(e *domain.Event) {
	if p == nil || p.conn == nil {
		return
	}
	if e.ID == "" {
		e.ID = id.New()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		slog.Warn("audit marshal failed", "err", err)
		return
	}
	if err := p.conn.Publish(Subject, b); err != nil {
		slog.Warn("audit publish failed", "err", err, "event_type", e.EventType)
	}
}
