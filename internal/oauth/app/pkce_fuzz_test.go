package app

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// FuzzVerifyPKCE feeds random verifier/challenge pairs to the PKCE checker
// to make sure no input causes a panic or — worse — a spurious match.
func FuzzVerifyPKCE(f *testing.F) {
	// Seed corpus
	f.Add("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	f.Add("", "")
	f.Add("a", "b")
	f.Add("\x00\x01\x02", "deadbeef")

	f.Fuzz(func(t *testing.T, verifier, challenge string) {
		ok := verifyPKCE(verifier, challenge)
		// Invariant: it can only return true when challenge is exactly the
		// base64url(sha256(verifier)) of the input verifier.
		if ok {
			sum := sha256.Sum256([]byte(verifier))
			want := base64.RawURLEncoding.EncodeToString(sum[:])
			if want != challenge {
				t.Fatalf("verifyPKCE returned true for non-matching pair: verifier=%q challenge=%q", verifier, challenge)
			}
		}
	})
}

func FuzzSplitScopes(f *testing.F) {
	f.Add("openid profile email")
	f.Add("")
	f.Add("   spaces   ")
	f.Add("\t\nweird whitespace")

	f.Fuzz(func(t *testing.T, s string) {
		got := splitScopes(s)
		// Each token must be non-empty (strings.Fields contract).
		for i, tok := range got {
			if tok == "" {
				t.Fatalf("splitScopes(%q)[%d] is empty: %v", s, i, got)
			}
		}
	})
}
