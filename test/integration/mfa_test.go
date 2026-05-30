package integration

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestMFA_FullFlow(t *testing.T) {
	requiresServer(t)
	c := New(t)
	email := UniqueEmail("mfa")
	c.Register(email, "password123", "MFA Test")
	c.Login(email, "password123")

	// Enroll
	resp, body := c.Post("/mfa/enroll/totp", map[string]string{"label": "Test Phone"})
	MustStatus(t, resp, body, 201, "enroll")
	var enroll struct {
		FactorID string `json:"factor_id"`
		Secret   string `json:"secret"`
		QRURL    string `json:"qr_url"`
	}
	_ = json.Unmarshal(body, &enroll)
	if enroll.Secret == "" || enroll.FactorID == "" {
		t.Fatal("enroll missing fields")
	}

	// Verify enrollment
	code, _ := totp.GenerateCode(enroll.Secret, time.Now().UTC())
	resp2, body2 := c.Post("/mfa/enroll/verify", map[string]string{
		"factor_id": enroll.FactorID, "code": code,
	})
	MustStatus(t, resp2, body2, 204, "verify enrollment")

	// Subsequent login returns MFA challenge
	c2 := New(t)
	resp3, body3 := c2.do("POST", "/login", map[string]string{
		"email": email, "password": "password123",
	}, nil)
	MustStatus(t, resp3, body3, 200, "login (mfa required)")
	var lr loginResp
	_ = json.Unmarshal(body3, &lr)
	if !lr.MFARequired || lr.MFAToken == "" {
		t.Fatalf("expected mfa challenge, got %s", body3)
	}
	if lr.AccessToken != "" {
		t.Error("login should not issue access_token when MFA required")
	}

	// Complete MFA
	code2, _ := totp.GenerateCode(enroll.Secret, time.Now().UTC())
	resp4, body4 := c2.do("POST", "/mfa/complete", map[string]string{
		"mfa_token": lr.MFAToken, "code": code2,
	}, nil)
	MustStatus(t, resp4, body4, 200, "mfa complete")

	var done loginResp
	_ = json.Unmarshal(body4, &done)
	if done.AccessToken == "" {
		t.Error("mfa complete did not issue access_token")
	}
}

func TestMFA_WrongCodeRejected(t *testing.T) {
	requiresServer(t)
	c := New(t)
	email := UniqueEmail("mfa-bad")
	c.Register(email, "password123", "MFA Bad")
	c.Login(email, "password123")

	resp, body := c.Post("/mfa/enroll/totp", map[string]string{"label": "x"})
	MustStatus(t, resp, body, 201, "enroll")
	var enroll struct {
		FactorID string `json:"factor_id"`
		Secret   string `json:"secret"`
	}
	_ = json.Unmarshal(body, &enroll)

	resp2, body2 := c.Post("/mfa/enroll/verify", map[string]string{
		"factor_id": enroll.FactorID, "code": "000000",
	})
	if resp2.StatusCode != 401 {
		t.Errorf("wrong enrollment code expected 401, got %d body=%s", resp2.StatusCode, body2)
	}
}

func TestMFA_ListFactors(t *testing.T) {
	requiresServer(t)
	c := New(t)
	c.Register(UniqueEmail("mfa-list"), "password123", "MFA List")
	c.Login(c.Email, "password123")

	resp, body := c.Get("/mfa/factors")
	MustStatus(t, resp, body, 200, "list (empty)")
	if string(body) != "[]\n" {
		t.Errorf("expected empty list, got %s", body)
	}

	_, body2 := c.Post("/mfa/enroll/totp", map[string]string{"label": "Phone"})
	var enroll struct{ FactorID string `json:"factor_id"` }
	_ = json.Unmarshal(body2, &enroll)

	resp3, body3 := c.Get("/mfa/factors")
	MustStatus(t, resp3, body3, 200, "list (one)")
	var factors []map[string]any
	_ = json.Unmarshal(body3, &factors)
	if len(factors) != 1 {
		t.Errorf("expected 1 factor, got %d", len(factors))
	}
}
