package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	authorizationapp "github.com/krishnaditya65/Project-Janus/internal/authorization/app"
	authctx "github.com/krishnaditya65/Project-Janus/internal/shared/context"
)

func (h *Handler) AssignPermission(
	w http.ResponseWriter,
	r *http.Request,
) {

	p, ok := authctx.Principal(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	roleID := chi.URLParam(r, "roleID")

	var req AssignPermissionRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	err := h.assignPermissionUseCase.Execute(
		r.Context(),
		authorizationapp.AssignPermissionToRoleInput{
			TenantID:       p.TenantID,
			RoleID:         roleID,
			PermissionName: req.Permission,
		},
	)

	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
