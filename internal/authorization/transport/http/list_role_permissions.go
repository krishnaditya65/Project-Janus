package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	authctx "github.com/krishnaditya65/Project-Janus/internal/shared/context"
)

func (h *Handler) ListRolePermissions(
	w http.ResponseWriter,
	r *http.Request,
) {

	p, ok := authctx.Principal(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	roleID := chi.URLParam(r, "roleID")

	permissions, err := h.listRolePermissionsUseCase.Execute(
		r.Context(),
		p.TenantID,
		roleID,
	)

	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(permissions)
}
