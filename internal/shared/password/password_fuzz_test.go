package password

import (
	"testing"
)

// FuzzVerify_NoPanic asserts that Verify never panics regardless of input.
// Past CVEs in argon2 wrappers have come from malformed encoded hashes that
// produced index-out-of-bounds or division-by-zero crashes.
func FuzzVerify_NoPanic(f *testing.F) {
	f.Add("password", "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA")
	f.Add("", "")
	f.Add("x", "$argon2id$v=19$broken")
	f.Add("x", "$$$$$$")

	f.Fuzz(func(t *testing.T, pw, hash string) {
		// Verify must return a bool without panicking. We don't care which.
		_ = Verify(pw, hash)
	})
}
