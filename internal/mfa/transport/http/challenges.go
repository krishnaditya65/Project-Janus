package http

import (
	"encoding/json"
	"errors"
	"net/http"

	mfaapp "github.com/krishnaditya65/Project-Janus/internal/mfa/app"
	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
)

// StoreChallenge handles POST /internal/mfa/challenges. The request body is
// the full mfaapp.Challenge, generated client-side by auth's LoginUseCase
// the same way it always was before this store moved behind HTTP.
func (h *InternalHandler) StoreChallenge(w http.ResponseWriter, r *http.Request) {
	var challenge mfaapp.Challenge
	if err := json.NewDecoder(r.Body).Decode(&challenge); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if err := h.challengeStore.Store(r.Context(), &challenge); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type consumeChallengeRequest struct {
	Token string `json:"token"`
}

// ConsumeChallenge handles POST /internal/mfa/challenges/consume. It is a
// POST (not a GET, despite being logically a read) because Consume is
// destructive - GetDel removes the challenge - and this mirrors the
// semantics of the original *mfaapp.ChallengeStore.Consume the two callers
// (auth's mfa completion flow and mfa's own CompleteUseCase) relied on.
func (h *InternalHandler) ConsumeChallenge(w http.ResponseWriter, r *http.Request) {
	var req consumeChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}

	challenge, err := h.challengeStore.Consume(r.Context(), req.Token)
	if err != nil {
		if errors.Is(err, sharederrors.ErrNotFound) {
			http.Error(w, "challenge not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(challenge)
}
