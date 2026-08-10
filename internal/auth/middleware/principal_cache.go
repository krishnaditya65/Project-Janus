package middleware

import (
	"context"
	"encoding/json"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/krishnaditya65/Project-Janus/internal/platform/metrics"
	"github.com/krishnaditya65/Project-Janus/internal/shared/principal"
)

// PrincipalCache stores the assembled Principal by session ID so the
// session-ID auth path can skip 4 sequential DB reads on every request.
//
// Invalidation: explicit Delete on logout; otherwise relies on TTL.
// Tradeoff: if roles/permissions change mid-session, the cached principal
// stays stale for up to ttl. ttl is short (5 min) by default.

const cachePrefix = "auth:principal:"
const defaultTTL = 5 * time.Minute

type PrincipalCache struct {
	client *goredis.Client
	ttl    time.Duration
}

func NewPrincipalCache(client *goredis.Client) *PrincipalCache {
	return &PrincipalCache{client: client, ttl: defaultTTL}
}

func (c *PrincipalCache) Get(ctx context.Context, sessionID string) (*principal.Principal, bool) {
	if c == nil || c.client == nil {
		return nil, false
	}
	b, err := c.client.Get(ctx, cachePrefix+sessionID).Bytes()
	if err != nil {
		metrics.PrincipalCacheMisses.Inc()
		return nil, false
	}
	cached := &principal.Principal{}
	if err := json.Unmarshal(b, cached); err != nil {
		metrics.PrincipalCacheMisses.Inc()
		return nil, false
	}
	metrics.PrincipalCacheHits.Inc()
	return cached, true
}

func (c *PrincipalCache) Put(ctx context.Context, p *principal.Principal) {
	if c == nil || c.client == nil || p == nil || p.SessionID == "" {
		return
	}
	b, err := json.Marshal(p)
	if err != nil {
		return
	}
	_ = c.client.Set(ctx, cachePrefix+p.SessionID, b, c.ttl).Err()
}

func (c *PrincipalCache) Delete(ctx context.Context, sessionID string) {
	if c == nil || c.client == nil {
		return
	}
	_ = c.client.Del(ctx, cachePrefix+sessionID).Err()
}
