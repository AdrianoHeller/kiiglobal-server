package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/AdrianoHeller/kii/client"
)

func TestTimestampValidation(t *testing.T) {
	s := NewServer(":0", nil)

	// Current timestamp should be valid
	now := time.Now().Unix()
	if !s.TimestampValidation(fmt.Sprintf("%d", now)) {
		t.Fatal("expected current timestamp to be valid")
	}

	// Very old timestamp should be invalid when TIMESTAMP_AGE is small
	os.Setenv("TIMESTAMP_AGE", "1s")
	old := time.Now().Add(-2 * time.Second).Unix()
	if s.TimestampValidation(fmt.Sprintf("%d", old)) {
		t.Fatal("expected old timestamp to be invalid")
	}
}

func TestWebhookHandler_Success(t *testing.T) {
	s := NewServer(":0", nil)
	accessKey := "test-access"
	secret := "secret123"
	s.SetSecretKey(accessKey, secret)
	s.AdminKey = "admin-secret"

	body := []byte(`{"user":"Alice","asset":"Gold","amount":10}`)
	nonce, err := client.GenerateNonce(16)
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}
	ts := time.Now().Unix()
	sig := s.ComputeHmacSignature(ts, body, nonce, secret)

	req := httptest.NewRequest("GET", "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Access-Key", accessKey)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Admin-Key", s.AdminKey)

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(s.WebhookHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200 OK, got %d, body: %s", rr.Code, rr.Body.String())
	}

	var got map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}
	if got["user"] != "Alice" {
		t.Fatalf("unexpected response JSON: %v", got)
	}
}
