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

			principal := authctx.MustPrincipal(
				r.Context(),
			)

			ctx := tenancy.WithTenant(
				r.Context(),
				principal.TenantID,
			)

			next.ServeHTTP(
				w,
				r.WithContext(ctx),
			)
		},
	)
}
