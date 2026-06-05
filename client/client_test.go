package client

import (
	"testing"
)

func TestGenerateNonce(t *testing.T) {
	n, err := GenerateNonce(16)
	if err != nil {
		t.Fatalf("GenerateNonce error: %v", err)
	}
	if n == "" {
		t.Fatalf("expected non-empty nonce")
	}
}
