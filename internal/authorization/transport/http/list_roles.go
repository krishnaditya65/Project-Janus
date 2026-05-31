package http

import (
	"encoding/json"
	"net/http"

	authctx "github.com/krishnaditya65/Project-Janus/internal/shared/context"
)

func (h *Handler) ListRoles(
	w http.ResponseWriter,
	r *http.Request,
) {

	p, ok := authctx.Principal(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	roles, err := h.listRolesUseCase.Execute(r.Context(), p.TenantID)

	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(roles)
}
