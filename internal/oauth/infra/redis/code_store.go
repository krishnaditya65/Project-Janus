package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/krishnaditya65/Project-Janus/internal/oauth/domain"
	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
)

const codePrefix = "oauth:code:"

type CodeStore struct {
	client *goredis.Client
}

func NewCodeStore(client *goredis.Client) *CodeStore {
	return &CodeStore{client: client}
}

func (s *CodeStore) Store(ctx context.Context, code *domain.AuthorizationCode) error {
	b, err := json.Marshal(code)
	if err != nil {
		return err
	}
	ttl := time.Until(code.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("code already expired")
	}
	return s.client.Set(ctx, codePrefix+code.Code, b, ttl).Err()
}

func (s *CodeStore) Consume(ctx context.Context, code string) (*domain.AuthorizationCode, error) {
	key := codePrefix + code
	b, err := s.client.GetDel(ctx, key).Bytes()
	if err == goredis.Nil {
		return nil, sharederrors.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c := &domain.AuthorizationCode{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	return c, nil
}
