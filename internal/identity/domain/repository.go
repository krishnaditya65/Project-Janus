package domain

import "context"

type Repository interface {
	Create(ctx context.Context, identity *Identity) error
	GetByEmail(ctx context.Context, email string) (*Identity, error)
	GetByID(ctx context.Context, id string) (*Identity, error)
	Delete(ctx context.Context, id string) error
}
