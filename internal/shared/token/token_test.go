package token

import (
	"encoding/base64"
	"testing"
)

func TestGenerateRandom_Length(t *testing.T) {
	cases := []int{8, 16, 32, 64}
	for _, n := range cases {
		s, err := GenerateRandom(n)
		if err != nil {
			t.Fatalf("len=%d: %v", n, err)
		}
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("len=%d: invalid base64url: %v", n, err)
		}
		if len(b) != n {
			t.Errorf("len=%d: decoded %d bytes", n, len(b))
		}
	}
}

func TestGenerateRandom_Unique(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		s, err := GenerateRandom(32)
		if err != nil {
			t.Fatal(err)
		}
		if seen[s] {
			t.Fatalf("collision after %d iterations: %s", i, s)
		}
		seen[s] = true
	}
}

func TestHash_Deterministic(t *testing.T) {
	a := Hash("hello")
	b := Hash("hello")
	if a != b {
		t.Errorf("Hash should be deterministic: %q != %q", a, b)
	}
}

func TestHash_DifferentInputs(t *testing.T) {
	if Hash("a") == Hash("b") {
		t.Error("different inputs should produce different hashes")
	}
}

func TestHash_HexFormatSHA256(t *testing.T) {
	h := Hash("anything")
	if len(h) != 64 {
		t.Errorf("expected 64 hex chars (SHA-256), got %d", len(h))
	}
	for _, c := range h {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("non-hex character %q in %q", c, h)
		}
	}
}
