package middleware

import (
	"net/http"

	authctx "github.com/krishnaditya65/Project-Janus/internal/shared/context"
)

func RequirePermission(
	permission string,
) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			p, ok := authctx.Principal(r.Context())
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if !p.HasPermission(permission) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
