package http

import (
	"encoding/json"
	"net/http"

	identityapp "github.com/krishnaditya65/Project-Janus/internal/identity/app"
	authctx "github.com/krishnaditya65/Project-Janus/internal/shared/context"
	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
)

type CreateUserRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	RoleName    string `json:"role_name"`
}

func (h *Handler) CreateUser(
	w http.ResponseWriter,
	r *http.Request,
) {

	p, ok := authctx.Principal(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req CreateUserRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	user, err := h.createUserUseCase.Execute(
		r.Context(),
		identityapp.CreateUserInput{
			TenantID:    p.TenantID,
			Email:       req.Email,
			Password:    req.Password,
			DisplayName: req.DisplayName,
			RoleName:    req.RoleName,
		},
	)

	if err != nil {
		if err == sharederrors.ErrConflict {
			http.Error(w, "email already exists", http.StatusConflict)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}
