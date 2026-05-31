package http

import (
	"net/http"

	authctx "github.com/krishnaditya65/Project-Janus/internal/shared/context"
)

func (h *Handler) Me(
	w http.ResponseWriter,
	r *http.Request,
) {
	p, ok := authctx.Principal(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	writeJSON(w, p)
}
