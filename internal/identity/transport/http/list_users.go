package http

import (
	"encoding/json"
	"net/http"

	authctx "github.com/krishnaditya65/Project-Janus/internal/shared/context"
)

func (h *Handler) ListUsers(
	w http.ResponseWriter,
	r *http.Request,
) {

	p, ok := authctx.Principal(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	users, err := h.listUsersUseCase.Execute(r.Context(), p.TenantID)

	if err != nil {
		http.Error(w, "failed to list users", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}
