package http

import (
	"encoding/json"
	"net/http"

	identitydomain "github.com/krishnaditya65/Project-Janus/internal/identity/domain"
	authctx "github.com/krishnaditya65/Project-Janus/internal/shared/context"
)

type UserInfoHandler struct {
	identityRepo identitydomain.Repository
}

func NewUserInfoHandler(identityRepo identitydomain.Repository) *UserInfoHandler {
	return &UserInfoHandler{identityRepo: identityRepo}
}

type userInfoResponse struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func (h *UserInfoHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	p, ok := authctx.Principal(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	resp := userInfoResponse{
		Sub:   p.IdentityID,
		Email: p.Email,
	}

	if identity, err := h.identityRepo.GetByID(r.Context(), p.IdentityID); err == nil {
		resp.EmailVerified = identity.EmailVerified
		if resp.Email == "" {
			resp.Email = identity.PrimaryEmail
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
