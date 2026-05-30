package password

import (
	"strings"
	"testing"
)

func TestHash_ProducesArgon2idFormat(t *testing.T) {
	hash, err := Hash("hunter2")
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Errorf("expected argon2id prefix, got %q", hash)
	}
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Errorf("expected 6 segments, got %d", len(parts))
	}
}

func TestHash_UniqueSaltsPerCall(t *testing.T) {
	h1, _ := Hash("same-password")
	h2, _ := Hash("same-password")
	if h1 == h2 {
		t.Error("two hashes of same password should differ (random salt)")
	}
}

func TestVerify_CorrectPassword(t *testing.T) {
	hash, _ := Hash("correct-horse-battery-staple")
	if !Verify("correct-horse-battery-staple", hash) {
		t.Error("Verify returned false for correct password")
	}
}

func TestVerify_WrongPassword(t *testing.T) {
	hash, _ := Hash("right")
	if Verify("wrong", hash) {
		t.Error("Verify returned true for wrong password")
	}
}

func TestVerify_MalformedHash(t *testing.T) {
	cases := []string{
		"",
		"not-a-hash",
		"$argon2id$only-three$segments$here",
		"$argon2id$v=19$m=65536,t=3,p=2$!!!invalidsalt!!!$validhash",
	}
	for _, c := range cases {
		if Verify("any", c) {
			t.Errorf("Verify should fail for malformed hash %q", c)
		}
	}
}

func TestVerify_EmptyPassword(t *testing.T) {
	hash, _ := Hash("")
	if !Verify("", hash) {
		t.Error("empty password should verify against its own hash")
	}
	if Verify("nonempty", hash) {
		t.Error("nonempty password should not verify against empty-password hash")
	}
}

func BenchmarkHash(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = Hash("benchmark-password")
	}
}

func BenchmarkVerify(b *testing.B) {
	hash, _ := Hash("benchmark-password")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Verify("benchmark-password", hash)
	}
}
