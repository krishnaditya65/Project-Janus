package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/krishnaditya65/Project-Janus/internal/audit/domain"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Insert(ctx context.Context, e *domain.Event) error {
	const q = `
		INSERT INTO audit_events
			(id, tenant_id, actor_identity_id, event_type, resource_type, resource_id, ip_address, payload, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7::inet, $8, $9)`

	var tenantID, actor, resType, resID, ip any
	if e.TenantID != "" {
		tenantID = e.TenantID
	}
	if e.ActorIdentityID != "" {
		actor = e.ActorIdentityID
	}
	if e.ResourceType != "" {
		resType = e.ResourceType
	}
	if e.ResourceID != "" {
		resID = e.ResourceID
	}
	if e.IPAddress != "" {
		ip = e.IPAddress
	}
	var payload any
	if len(e.Payload) > 0 {
		payload = []byte(e.Payload)
	}

	_, err := r.db.Exec(ctx, q, e.ID, tenantID, actor, e.EventType, resType, resID, ip, payload, e.CreatedAt)
	return err
}
