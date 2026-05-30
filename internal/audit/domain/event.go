package domain

import (
	"context"
	"encoding/json"
	"time"
)

const (
	EventLogin           = "auth.login"
	EventLoginFailed     = "auth.login_failed"
	EventLogout          = "auth.logout"
	EventRefresh         = "auth.refresh"
	EventRegister        = "auth.register"
	EventMFAEnrolled     = "mfa.enrolled"
	EventMFAVerified     = "mfa.verified"
	EventMFAComplete     = "mfa.complete"
	EventOAuthAuthorize  = "oauth.authorize"
	EventOAuthToken      = "oauth.token"
	EventOAuthCodeReused = "oauth.code_reused"
)

type Event struct {
	ID              string          `json:"id"`
	TenantID        string          `json:"tenant_id,omitempty"`
	ActorIdentityID string          `json:"actor_identity_id,omitempty"`
	EventType       string          `json:"event_type"`
	ResourceType    string          `json:"resource_type,omitempty"`
	ResourceID      string          `json:"resource_id,omitempty"`
	IPAddress       string          `json:"ip_address,omitempty"`
	Payload         json.RawMessage `json:"payload,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
}

type Repository interface {
	Insert(ctx context.Context, e *Event) error
}
