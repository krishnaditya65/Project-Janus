package http

import (
	"encoding/json"
	"net/http"

	authorizationapp "github.com/krishnaditya65/Project-Janus/internal/authorization/app"
	authctx "github.com/krishnaditya65/Project-Janus/internal/shared/context"
	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
)

func (h *Handler) CreateRole(
	w http.ResponseWriter,
	r *http.Request,
) {

	p, ok := authctx.Principal(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req CreateRoleRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	err := h.createRoleUseCase.Execute(
		r.Context(),
		authorizationapp.CreateRoleInput{
			TenantID:    p.TenantID,
			Name:        req.Name,
			Description: req.Description,
		},
	)

	if err != nil {
		if err == sharederrors.ErrConflict {
			http.Error(w, "role already exists", http.StatusConflict)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
