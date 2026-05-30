package integration

import (
	"encoding/json"
	"testing"
)

// WebAuthn requires a real authenticator (browser/Touch ID/YubiKey) to complete the ceremony.
// We can only verify the server-side challenge generation here.

func TestWebAuthn_RegisterBeginReturnsValidOptions(t *testing.T) {
	requiresServer(t)
	c := authedClient(t, "wa-reg")
	resp, body := c.Post("/webauthn/register/begin", nil)
	MustStatus(t, resp, body, 200, "register begin")

	var r struct {
		SessionKey string `json:"session_key"`
		Options    struct {
			PublicKey struct {
				Rp struct {
					Name string `json:"name"`
					ID   string `json:"id"`
				} `json:"rp"`
				User struct {
					ID          string `json:"id"`
					Name        string `json:"name"`
					DisplayName string `json:"displayName"`
				} `json:"user"`
				Challenge        string `json:"challenge"`
				PubKeyCredParams []struct {
					Alg int `json:"alg"`
				} `json:"pubKeyCredParams"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatal(err)
	}
	if r.SessionKey == "" {
		t.Error("missing session_key")
	}
	if r.Options.PublicKey.Challenge == "" {
		t.Error("missing challenge")
	}
	if r.Options.PublicKey.Rp.ID == "" {
		t.Error("missing rp.id")
	}
	if r.Options.PublicKey.User.Name != c.Email {
		t.Errorf("user.name should be email: got %q want %q", r.Options.PublicKey.User.Name, c.Email)
	}
	if len(r.Options.PublicKey.PubKeyCredParams) == 0 {
		t.Error("no pubKeyCredParams")
	}
}

func TestWebAuthn_LoginBeginReturnsDiscoverableChallenge(t *testing.T) {
	requiresServer(t)
	c := New(t)
	resp, body := c.do("POST", "/webauthn/login/begin", nil, nil)
	MustStatus(t, resp, body, 200, "login begin")
	var r struct {
		SessionKey string `json:"session_key"`
		Options    struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
				RpID      string `json:"rpId"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatal(err)
	}
	if r.SessionKey == "" || r.Options.PublicKey.Challenge == "" {
		t.Errorf("missing session_key or challenge: %s", body)
	}
}

func TestWebAuthn_CredentialsListEmpty(t *testing.T) {
	requiresServer(t)
	c := authedClient(t, "wa-list")
	resp, body := c.Get("/webauthn/credentials")
	MustStatus(t, resp, body, 200, "list credentials")
	if string(body) != "[]\n" {
		t.Errorf("expected empty list, got %s", body)
	}
}
