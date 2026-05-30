package app

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestVerifyPKCE_MatchingPair(t *testing.T) {
	v := "the-quick-brown-fox-jumps-over-the-lazy-dog-1234567890"
	c := challengeFor(v)
	if !verifyPKCE(v, c) {
		t.Error("expected matching verifier/challenge to pass")
	}
}

func TestVerifyPKCE_Mismatch(t *testing.T) {
	v := "verifier-A-verifier-A-verifier-A-verifier-A-1234567"
	wrongChallenge := challengeFor("verifier-B-verifier-B-verifier-B-verifier-B-7654321")
	if verifyPKCE(v, wrongChallenge) {
		t.Error("expected mismatched verifier/challenge to fail")
	}
}

func TestVerifyPKCE_EmptyVerifier(t *testing.T) {
	c := challengeFor("real-verifier")
	if verifyPKCE("", c) {
		t.Error("empty verifier should not pass against real challenge")
	}
}

func TestVerifyPKCE_RFC7636Example(t *testing.T) {
	// RFC 7636 Appendix B
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	expected := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if challengeFor(verifier) != expected {
		t.Errorf("RFC 7636 vector mismatch: got %q want %q", challengeFor(verifier), expected)
	}
	if !verifyPKCE(verifier, expected) {
		t.Error("RFC 7636 vector failed verify")
	}
}

func TestSplitScopes(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"openid", 1},
		{"openid profile email", 3},
		{"  openid    profile  ", 2},
	}
	for _, c := range cases {
		got := splitScopes(c.in)
		if len(got) != c.want {
			t.Errorf("splitScopes(%q) = %v (len %d), want len %d", c.in, got, len(got), c.want)
		}
	}
}

func TestHasScope(t *testing.T) {
	scopes := []string{"openid", "profile", "email"}
	if !hasScope(scopes, "openid") {
		t.Error("openid should be present")
	}
	if hasScope(scopes, "offline_access") {
		t.Error("offline_access should not be present")
	}
	if hasScope(nil, "anything") {
		t.Error("nil slice should never report scope present")
	}
}
