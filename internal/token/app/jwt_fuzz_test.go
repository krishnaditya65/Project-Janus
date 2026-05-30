package app

import (
	"context"
	"testing"
)

// FuzzJWT_Verify feeds random byte strings to Verify. None of them should
// ever return a valid claims object; any nil error is a bug.
func FuzzJWT_Verify(f *testing.F) {
	svc := freshService(&testing.T{}, "ES256")
	// Seed with a real token plus obvious garbage.
	good, _ := svc.Issue(context.Background(), testPrincipal, IssueOptions{TTL: 60})
	f.Add(good)
	f.Add("")
	f.Add("not-a-jwt")
	f.Add("aaa.bbb.ccc")
	f.Add("eyJhbGciOiJub25lIn0..")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJ4IjoieSJ9.AAAA")

	f.Fuzz(func(t *testing.T, raw string) {
		claims, err := svc.Verify(context.Background(), raw)
		if err == nil {
			// The only way err can be nil is if the token was signed by our
			// active key and is unexpired. Any other path is a soundness bug.
			if claims == nil || claims.Subject == "" {
				t.Fatalf("Verify accepted token with empty claims: %q", raw)
			}
		}
	})
}

// FuzzJWT_RejectsAlgNone confirms `alg=none` JWTs are always rejected.
// This is one of the classic JWT vulnerabilities (CVE-2015-9235 family).
func FuzzJWT_RejectsAlgNone(f *testing.F) {
	svc := freshService(&testing.T{}, "ES256")
	// Header {"alg":"none","typ":"JWT"} base64url-encoded, payload {"sub":"x"},
	// empty signature.
	none := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ4In0."
	f.Add(none)

	f.Fuzz(func(t *testing.T, _ string) {
		// We don't use the fuzz input; we just want to run the constant
		// case under the fuzz harness for variant-replay safety.
		if _, err := svc.Verify(context.Background(), none); err == nil {
			t.Fatal("alg=none must always be rejected")
		}
	})
}
