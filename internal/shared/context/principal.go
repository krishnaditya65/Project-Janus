package context

import (
	"context"

	"github.com/krishnaditya65/Project-Janus/internal/shared/principal"
)

type contextKey string

const principalKey contextKey = "principal"

func WithPrincipal(
	ctx context.Context,
	p *principal.Principal,
) context.Context {
	return context.WithValue(
		ctx,
		principalKey,
		p,
	)
}

func Principal(
	ctx context.Context,
) (*principal.Principal, bool) {

	p, ok := ctx.Value(
		principalKey,
	).(*principal.Principal)

	return p, ok
}

func MustPrincipal(
	ctx context.Context,
) *principal.Principal {

	p, ok := Principal(ctx)

	if !ok {
		panic("principal missing from context")
	}

	return p
}
