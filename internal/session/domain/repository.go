package domain

import (
	"context"
	"time"
)

type Repository interface {
	Create(
		ctx context.Context,
		session *Session,
	) error

	GetByID(
		ctx context.Context,
		id string,
	) (*Session, error)

	GetByRefreshTokenHash(
		ctx context.Context,
		hash string,
	) (*Session, error)
	Revoke(
		ctx context.Context,
		id string,
	) error

	DeleteExpiredOrRevoked(
		ctx context.Context,
		olderThan time.Time,
	) (int64, error)
}
