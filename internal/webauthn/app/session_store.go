package app

import (
	"context"
	"encoding/json"
	"time"

	wa "github.com/go-webauthn/webauthn/webauthn"
	goredis "github.com/redis/go-redis/v9"

	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
)

const sessionTTL = 5 * time.Minute

type SessionStore struct {
	client *goredis.Client
}

func NewSessionStore(client *goredis.Client) *SessionStore {
	return &SessionStore{client: client}
}

func (s *SessionStore) Store(ctx context.Context, key string, data *wa.SessionData) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, "webauthn:session:"+key, b, sessionTTL).Err()
}

func (s *SessionStore) Consume(ctx context.Context, key string) (*wa.SessionData, error) {
	b, err := s.client.GetDel(ctx, "webauthn:session:"+key).Bytes()
	if err == goredis.Nil {
		return nil, sharederrors.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := &wa.SessionData{}
	if err := json.Unmarshal(b, d); err != nil {
		return nil, err
	}
	return d, nil
}
