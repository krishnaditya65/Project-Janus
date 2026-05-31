package app

import (
	"context"
	"encoding/json"
	"time"

	goredis "github.com/redis/go-redis/v9"

	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
)

const challengePrefix = "mfa:challenge:"
const challengeTTL = 5 * time.Minute

type Challenge struct {
	Token      string    `json:"token"`
	IdentityID string    `json:"identity_id"`
	TenantID   string    `json:"tenant_id"`
	UserID     string    `json:"user_id"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type ChallengeStore struct {
	client *goredis.Client
}

func NewChallengeStore(client *goredis.Client) *ChallengeStore {
	return &ChallengeStore{client: client}
}

func (s *ChallengeStore) Store(ctx context.Context, c *Challenge) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, challengePrefix+c.Token, b, challengeTTL).Err()
}

func (s *ChallengeStore) Consume(ctx context.Context, token string) (*Challenge, error) {
	b, err := s.client.GetDel(ctx, challengePrefix+token).Bytes()
	if err == goredis.Nil {
		return nil, sharederrors.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c := &Challenge{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	return c, nil
}
