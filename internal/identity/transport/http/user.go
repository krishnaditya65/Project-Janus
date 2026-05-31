package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	identityapp "github.com/krishnaditya65/Project-Janus/internal/identity/app"
	authctx "github.com/krishnaditya65/Project-Janus/internal/shared/context"
)

func (h *Handler) GetUser(
	w http.ResponseWriter,
	r *http.Request,
) {

	p, ok := authctx.Principal(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	userID := chi.URLParam(r, "userID")

	user, err := h.getUserUseCase.Execute(
		r.Context(),
		identityapp.GetUserInput{
			TenantID: p.TenantID,
			UserID:   userID,
		},
	)

	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}
