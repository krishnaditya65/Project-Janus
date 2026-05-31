package http

import (
	"encoding/json"
	"net/http"

	authapp "github.com/krishnaditya65/Project-Janus/internal/auth/app"
	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
)

type Handler struct {
	registerUseCase *authapp.RegisterUseCase
	loginUseCase    *authapp.LoginUseCase
	refreshUseCase  *authapp.RefreshUseCase
	logoutUseCase   *authapp.LogoutUseCase
}

func NewHandler(
	registerUseCase *authapp.RegisterUseCase,
	loginUseCase *authapp.LoginUseCase,
	refreshUseCase *authapp.RefreshUseCase,
	logoutUseCase *authapp.LogoutUseCase,
) *Handler {

	return &Handler{
		registerUseCase: registerUseCase,
		loginUseCase:    loginUseCase,
		refreshUseCase:  refreshUseCase,
		logoutUseCase:   logoutUseCase,
	}
}

func (h *Handler) Register(
	w http.ResponseWriter,
	r *http.Request,
) {
	var req RegisterRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, "email and password are required", http.StatusBadRequest)
		return
	}

	if !isValidEmail(req.Email) {
		writeError(w, "invalid email format", http.StatusBadRequest)
		return
	}

	if len(req.Password) < 8 {
		writeError(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	err := h.registerUseCase.Execute(
		r.Context(),
		authapp.RegisterInput{
			Email:    req.Email,
			Password: req.Password,
		},
	)

	if err != nil {
		if err == sharederrors.ErrConflict {
			writeError(w, "email already registered", http.StatusConflict)
			return
		}
		writeError(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(RegisterResponse{Message: "registration successful"})
}
