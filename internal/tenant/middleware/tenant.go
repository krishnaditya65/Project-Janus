package middleware

import (
	authctx "github.com/krishnaditya65/Project-Janus/internal/shared/context"
	"github.com/krishnaditya65/Project-Janus/internal/shared/tenancy"

	"net/http"
)

func ResolveTenant(
	next http.Handler,
) http.Handler {

	return http.HandlerFunc(
		func(
			w http.ResponseWriter,
			r *http.Request,
		) {

			p := authctx.MustPrincipal(
				r.Context(),
			)

			ctx := tenancy.WithTenant(
				r.Context(),
				p.TenantID,
			)

			next.ServeHTTP(
				w,
				r.WithContext(ctx),
			)
		},
	)
}
