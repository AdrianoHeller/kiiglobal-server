package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
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

	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
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

	var got Input
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}
	if got.User != "Alice" || got.Asset != "Gold" || got.Amount.String() != "10" {
		t.Fatalf("unexpected input response: %#v", got)
	}
}

func TestWebhookHandler_PrecisionDecimalAmount(t *testing.T) {
	s := NewServer(":0", nil)
	s.SetSecretKey("test-access", "secret123")
	s.AdminKey = "admin-secret"

	body := []byte(`{"user":"Alice","asset":"Gold","amount":0.1}`)
	nonce, err := client.GenerateNonce(16)
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}
	ts := time.Now().Unix()
	sig := s.ComputeHmacSignature(ts, body, nonce, "secret123")

	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Access-Key", "test-access")
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Admin-Key", s.AdminKey)

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.WebhookHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d, body=%s", rr.Code, rr.Body.String())
	}

	user, found := s.GetUser("Alice")
	if !found {
		t.Fatal("expected user Alice to exist")
	}
	if user.Balances["Gold"] != "0.10" {
		t.Fatalf("expected precise balance 0.10, got %q", user.Balances["Gold"])
	}
}

func TestWebhookHandler_RecordsLedgerTransaction(t *testing.T) {
	s := NewServer(":0", nil)
	s.SetSecretKey("test-access", "secret123")
	s.AdminKey = "admin-secret"

	body := []byte(`{"user":"Alice","asset":"Gold","amount":0.1}`)
	nonce, err := client.GenerateNonce(16)
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}
	ts := time.Now().Unix()
	sig := s.ComputeHmacSignature(ts, body, nonce, "secret123")

	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Access-Key", "test-access")
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Admin-Key", s.AdminKey)

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.WebhookHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d, body=%s", rr.Code, rr.Body.String())
	}

	ledger := s.GetLedger()
	if len(ledger) != 1 {
		t.Fatalf("expected 1 ledger entry, got %d", len(ledger))
	}
	if ledger[0].User != "Alice" || ledger[0].Asset != "Gold" || ledger[0].Amount != "0.10" {
		t.Fatalf("unexpected ledger entry: %#v", ledger[0])
	}
	if ledger[0].Signature != sig {
		t.Fatalf("expected request signature %q, got %q", sig, ledger[0].Signature)
	}
	if ledger[0].PreviousTransactionSignature != "" {
		t.Fatalf("expected empty previous transaction signature, got %q", ledger[0].PreviousTransactionSignature)
	}
}

func TestWebhookHandler_RecordsPreviousTransactionSignature(t *testing.T) {
	s := NewServer(":0", nil)
	s.SetSecretKey("test-access", "secret123")
	s.AdminKey = "admin-secret"

	body1 := []byte(`{"user":"Alice","asset":"Gold","amount":0.1}`)
	nonce1, err := client.GenerateNonce(16)
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}
	ts1 := time.Now().Unix()
	sig1 := s.ComputeHmacSignature(ts1, body1, nonce1, "secret123")

	req1 := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body1))
	req1.Header.Set("X-Access-Key", "test-access")
	req1.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts1))
	req1.Header.Set("X-Nonce", nonce1)
	req1.Header.Set("X-Signature", sig1)
	req1.Header.Set("X-Admin-Key", s.AdminKey)

	rr1 := httptest.NewRecorder()
	http.HandlerFunc(s.WebhookHandler).ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for first request, got %d, body=%s", rr1.Code, rr1.Body.String())
	}

	body2 := []byte(`{"user":"Alice","asset":"Gold","amount":0.2}`)
	nonce2, err := client.GenerateNonce(16)
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}
	ts2 := time.Now().Add(1 * time.Second).Unix()
	sig2 := s.ComputeHmacSignature(ts2, body2, nonce2, "secret123")

	req2 := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body2))
	req2.Header.Set("X-Access-Key", "test-access")
	req2.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts2))
	req2.Header.Set("X-Nonce", nonce2)
	req2.Header.Set("X-Signature", sig2)
	req2.Header.Set("X-Admin-Key", s.AdminKey)

	rr2 := httptest.NewRecorder()
	http.HandlerFunc(s.WebhookHandler).ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for second request, got %d, body=%s", rr2.Code, rr2.Body.String())
	}

	ledger := s.GetLedger()
	if len(ledger) != 2 {
		t.Fatalf("expected 2 ledger entries, got %d", len(ledger))
	}
	if ledger[1].Signature != sig2 {
		t.Fatalf("expected second entry signature %q, got %q", sig2, ledger[1].Signature)
	}
	if ledger[1].PreviousTransactionSignature != sig1 {
		t.Fatalf("expected second entry previous signature %q, got %q", sig1, ledger[1].PreviousTransactionSignature)
	}
}

func TestCheckUserDoesNotOverwriteBalances(t *testing.T) {
	s := NewServer(":0", nil)
	s.Users = []User{{Name: "Alice", Balances: map[string]string{"Gold": "10.00"}}}

	s.CheckUser(User{Name: "Alice", Balances: map[string]string{}})

	user, found := s.GetUser("Alice")
	if !found {
		t.Fatal("expected user Alice to still exist")
	}
	if user.Balances["Gold"] != "10.00" {
		t.Fatalf("expected existing balance to remain 10.00, got %q", user.Balances["Gold"])
	}
}

func TestModifyUserBalancePrecision(t *testing.T) {
	s := NewServer(":0", nil)
	s.Users = []User{{Name: "Alice", Balances: map[string]string{"Gold": "0.00"}}}
	w := httptest.NewRecorder()

	if !s.ModifyUserBalance("Alice", "Gold", "0.10", w) {
		t.Fatal("expected first update to succeed")
	}
	if !s.ModifyUserBalance("Alice", "Gold", "0.20", w) {
		t.Fatal("expected second update to succeed")
	}

	user, found := s.GetUser("Alice")
	if !found {
		t.Fatal("expected user Alice to exist")
	}
	if user.Balances["Gold"] != "0.30" {
		t.Fatalf("expected precise balance 0.30, got %q", user.Balances["Gold"])
	}
}

func TestModifyUserBalance_InvalidAmountFormat(t *testing.T) {
	s := NewServer(":0", nil)
	s.Users = []User{{Name: "Alice", Balances: map[string]string{"Gold": "0.00"}}}
	w := httptest.NewRecorder()

	if s.ModifyUserBalance("Alice", "Gold", "abc", w) {
		t.Fatal("expected invalid amount update to fail")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request status code, got %d", w.Code)
	}
}

func TestUserDetailHandler_ReturnsUserWithBalances(t *testing.T) {
	s := NewServer(":0", nil)
	s.AdminKey = "admin-secret"
	s.Users = []User{{Name: "Alice", Balances: map[string]string{"Gold": "10.00", "Silver": "5.50"}}}

	req := httptest.NewRequest("GET", "/balance/Alice", nil)
	req.Header.Set("X-Admin-Key", s.AdminKey)
	req.Header.Set("X-Signature", "dummy")
	req.Header.Set("X-Nonce", "dummy")

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.UserDetailHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d, body=%s", rr.Code, rr.Body.String())
	}

	var got User
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}

	if got.Name != "Alice" {
		t.Fatalf("expected user Alice, got %q", got.Name)
	}
	if got.Balances["Gold"] != "10.00" || got.Balances["Silver"] != "5.50" {
		t.Fatalf("unexpected balances: %#v", got.Balances)
	}
}

func TestWebhookHandler_InvalidAccessKey(t *testing.T) {
	s := NewServer(":0", nil)
	s.SetSecretKey("good-access", "secret123")
	s.AdminKey = "admin-secret"

	body := []byte(`{"user":"Alice","asset":"Gold","amount":10}`)
	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Access-Key", "bad-access")
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	req.Header.Set("X-Nonce", "nonce-1")
	req.Header.Set("X-Signature", "dummy")
	req.Header.Set("X-Admin-Key", s.AdminKey)

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.WebhookHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestWebhookHandler_MissingHeaders(t *testing.T) {
	s := NewServer(":0", nil)
	s.SetSecretKey("test-access", "secret123")
	s.AdminKey = "admin-secret"

	body := []byte(`{"user":"Alice","asset":"Gold","amount":10}`)
	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Access-Key", "test-access")
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	req.Header.Set("X-Admin-Key", s.AdminKey)

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.WebhookHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestWebhookHandler_InvalidJSONBody(t *testing.T) {
	s := NewServer(":0", nil)
	s.SetSecretKey("test-access", "secret123")
	s.AdminKey = "admin-secret"

	body := []byte(`{"user":"Alice","asset":"Gold","amount":10`)
	nonce, err := client.GenerateNonce(16)
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}
	ts := time.Now().Unix()
	sig := s.ComputeHmacSignature(ts, body, nonce, "secret123")

	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Access-Key", "test-access")
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Admin-Key", s.AdminKey)

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.WebhookHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestWebhookHandler_MissingPayloadFields(t *testing.T) {
	s := NewServer(":0", nil)
	s.SetSecretKey("test-access", "secret123")
	s.AdminKey = "admin-secret"

	body := []byte(`{"user":"","asset":"Gold","amount":10}`)
	nonce, err := client.GenerateNonce(16)
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}
	ts := time.Now().Unix()
	sig := s.ComputeHmacSignature(ts, body, nonce, "secret123")

	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Access-Key", "test-access")
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Admin-Key", s.AdminKey)

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.WebhookHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestWebhookHandler_InvalidTimestampFormat(t *testing.T) {
	s := NewServer(":0", nil)
	s.SetSecretKey("test-access", "secret123")
	s.AdminKey = "admin-secret"

	body := []byte(`{"user":"Alice","asset":"Gold","amount":10}`)
	nonce, err := client.GenerateNonce(16)
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}

	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Access-Key", "test-access")
	req.Header.Set("X-Timestamp", "not-a-timestamp")
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", "dummy")
	req.Header.Set("X-Admin-Key", s.AdminKey)

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.WebhookHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestWebhookHandler_MethodNotAllowed(t *testing.T) {
	s := NewServer(":0", nil)
	s.SetSecretKey("test-access", "secret123")
	s.AdminKey = "admin-secret"

	body := []byte(`{"user":"Alice","asset":"Gold","amount":10}`)
	nonce, err := client.GenerateNonce(16)
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}
	ts := time.Now().Unix()
	sig := s.ComputeHmacSignature(ts, body, nonce, "secret123")

	req := httptest.NewRequest("GET", "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Access-Key", "test-access")
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Admin-Key", s.AdminKey)

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.WebhookHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestWebhookHandler_InvalidAmountFormat(t *testing.T) {
	s := NewServer(":0", nil)
	s.SetSecretKey("test-access", "secret123")
	s.AdminKey = "admin-secret"

	body := []byte(`{"user":"Alice","asset":"Gold","amount":"abc"}`)
	nonce, err := client.GenerateNonce(16)
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}
	ts := time.Now().Unix()
	sig := s.ComputeHmacSignature(ts, body, nonce, "secret123")

	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Access-Key", "test-access")
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Admin-Key", s.AdminKey)

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.WebhookHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestUserHandler_ReturnsUsers(t *testing.T) {
	s := NewServer(":0", nil)
	s.AdminKey = "admin-secret"
	s.Users = []User{{Name: "Alice", Balances: map[string]string{"Gold": "10.00"}}}

	req := httptest.NewRequest("GET", "/users", nil)
	req.Header.Set("X-Admin-Key", s.AdminKey)
	req.Header.Set("X-Signature", "dummy")
	req.Header.Set("X-Nonce", "dummy")

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.UserHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d, body=%s", rr.Code, rr.Body.String())
	}

	var got []User
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}
	if len(got) != 1 || got[0].Name != "Alice" {
		t.Fatalf("unexpected users response: %#v", got)
	}
}

func TestLedgerHandler_ReturnsLedger(t *testing.T) {
	s := NewServer(":0", nil)
	s.AdminKey = "admin-secret"
	s.Ledger = []Transaction{
		{User: "Alice", Asset: "Gold", Amount: "10.00", Signature: "sig1", PreviousTransactionSignature: ""},
		{User: "Bob", Asset: "Silver", Amount: "5.50", Signature: "sig2", PreviousTransactionSignature: "sig1"},
	}

	req := httptest.NewRequest("GET", "/ledger", nil)
	req.Header.Set("X-Admin-Key", s.AdminKey)
	req.Header.Set("X-Signature", "dummy")
	req.Header.Set("X-Nonce", "dummy")

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.LedgerHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d, body=%s", rr.Code, rr.Body.String())
	}

	var got []Transaction
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}
	if len(got) != 2 || got[0].Signature != "sig1" || got[1].PreviousTransactionSignature != "sig1" {
		t.Fatalf("unexpected ledger response: %#v", got)
	}
}

func TestLedgerHandler_MethodNotAllowed(t *testing.T) {
	s := NewServer(":0", nil)
	s.AdminKey = "admin-secret"

	req := httptest.NewRequest("POST", "/ledger", nil)
	req.Header.Set("X-Admin-Key", s.AdminKey)
	req.Header.Set("X-Signature", "dummy")
	req.Header.Set("X-Nonce", "dummy")

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.LedgerHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestLedgerHandler_Unauthorized(t *testing.T) {
	s := NewServer(":0", nil)
	s.AdminKey = "admin-secret"

	req := httptest.NewRequest("GET", "/ledger", nil)
	req.Header.Set("X-Signature", "dummy")
	req.Header.Set("X-Nonce", "dummy")

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.LedgerHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestUserHandler_Unauthorized(t *testing.T) {
	s := NewServer(":0", nil)
	s.Users = []User{{Name: "Alice", Balances: map[string]string{"Gold": "10.00"}}}

	req := httptest.NewRequest("GET", "/users", nil)
	req.Header.Set("X-Signature", "dummy")
	req.Header.Set("X-Nonce", "dummy")

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.UserHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestUserHandler_MissingSignatureOrNonce(t *testing.T) {
	s := NewServer(":0", nil)
	s.AdminKey = "admin-secret"

	req := httptest.NewRequest("GET", "/users", nil)
	req.Header.Set("X-Admin-Key", s.AdminKey)

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.UserHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized when signature or nonce is missing, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestUserHandler_MethodNotAllowed(t *testing.T) {
	s := NewServer(":0", nil)
	s.AdminKey = "admin-secret"

	req := httptest.NewRequest("POST", "/users", nil)
	req.Header.Set("X-Admin-Key", s.AdminKey)
	req.Header.Set("X-Signature", "dummy")
	req.Header.Set("X-Nonce", "dummy")

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.UserHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestUserDetailHandler_NotFound(t *testing.T) {
	s := NewServer(":0", nil)
	s.AdminKey = "admin-secret"

	req := httptest.NewRequest("GET", "/balance/Bob", nil)
	req.Header.Set("X-Admin-Key", s.AdminKey)
	req.Header.Set("X-Signature", "dummy")
	req.Header.Set("X-Nonce", "dummy")

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.UserDetailHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestUserDetailHandler_InvalidPath(t *testing.T) {
	s := NewServer(":0", nil)
	s.AdminKey = "admin-secret"

	req := httptest.NewRequest("GET", "/balance", nil)
	req.Header.Set("X-Admin-Key", s.AdminKey)
	req.Header.Set("X-Signature", "dummy")
	req.Header.Set("X-Nonce", "dummy")

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.UserDetailHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestUserDetailHandler_Unauthorized(t *testing.T) {
	s := NewServer(":0", nil)
	s.AdminKey = "admin-secret"

	req := httptest.NewRequest("GET", "/balance/Alice", nil)
	req.Header.Set("X-Signature", "dummy")
	req.Header.Set("X-Nonce", "dummy")

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.UserDetailHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestUserDetailHandler_MethodNotAllowed(t *testing.T) {
	s := NewServer(":0", nil)
	s.AdminKey = "admin-secret"

	req := httptest.NewRequest("POST", "/balance/Alice", nil)
	req.Header.Set("X-Admin-Key", s.AdminKey)
	req.Header.Set("X-Signature", "dummy")
	req.Header.Set("X-Nonce", "dummy")

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.UserDetailHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestNonceHandler_Success(t *testing.T) {
	s := NewServer(":0", nil)
	s.AdminKey = "admin-secret"
	s.AddNonceFromRequest("nonce-1")

	req := httptest.NewRequest("GET", "/nonces", nil)
	req.Header.Set("X-Admin-Key", s.AdminKey)
	req.Header.Set("X-Signature", "dummy")
	req.Header.Set("X-Nonce", "dummy")

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.NonceHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d, body=%s", rr.Code, rr.Body.String())
	}

	var got map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to parse nonce response: %v", err)
	}
	if _, ok := got["nonce-1"]; !ok {
		t.Fatalf("expected stored nonce in response, got %#v", got)
	}
}

func TestNonceHandler_MethodNotAllowed(t *testing.T) {
	s := NewServer(":0", nil)
	s.AdminKey = "admin-secret"

	req := httptest.NewRequest("POST", "/nonces", nil)
	req.Header.Set("X-Admin-Key", s.AdminKey)
	req.Header.Set("X-Signature", "dummy")
	req.Header.Set("X-Nonce", "dummy")

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.NonceHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestNonceHandler_Unauthorized(t *testing.T) {
	s := NewServer(":0", nil)

	req := httptest.NewRequest("GET", "/nonces", nil)
	req.Header.Set("X-Signature", "dummy")
	req.Header.Set("X-Nonce", "dummy")

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.NonceHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func makeSignedWebhookRequest(t *testing.T, body []byte, accessKey, secretKey, adminKey string, ts int64, nonce string) *http.Request {
	t.Helper()
	if nonce == "" {
		var err error
		nonce, err = client.GenerateNonce(16)
		if err != nil {
			t.Fatalf("failed to generate nonce: %v", err)
		}
	}
	if ts == 0 {
		ts = time.Now().Unix()
	}

	bodyHash := sha256.Sum256(body)
	canonical := fmt.Sprintf("%d\n%s\n%s", ts, nonce, hex.EncodeToString(bodyHash[:]))
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(canonical))
	sig := hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Access-Key", accessKey)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Admin-Key", adminKey)
	return req
}

func TestWebhookHandler_HMACValidationScenarios(t *testing.T) {
	s := NewServer(":0", nil)
	accessKey := "test-access"
	secret := "secret123"
	s.SetSecretKey(accessKey, secret)
	s.AdminKey = "admin-secret"

	body := []byte(`{"user":"Alice","asset":"Gold","amount":10}`)
	validNonce, err := client.GenerateNonce(16)
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}
	badNonce, err := client.GenerateNonce(16)
	if err != nil {
		t.Fatalf("failed to generate bad nonce: %v", err)
	}

	tests := []struct {
		name        string
		timestamp   int64
		nonce       string
		signature   string
		adminKey    string
		expectCode  int
		expectError string
	}{
		{
			name:       "valid request",
			timestamp:  time.Now().Unix(),
			adminKey:   s.AdminKey,
			expectCode: http.StatusOK,
		},
		{
			name:        "invalid signature",
			timestamp:   time.Now().Unix(),
			nonce:       badNonce,
			signature:   "bad-signature",
			adminKey:    s.AdminKey,
			expectCode:  http.StatusUnauthorized,
			expectError: "Invalid Signature",
		},
		{
			name:        "expired timestamp",
			timestamp:   time.Now().Add(-10 * time.Minute).Unix(),
			adminKey:    s.AdminKey,
			expectCode:  http.StatusUnauthorized,
			expectError: "Invalid or expired timestamp",
		},
		{
			name:        "nonce replay",
			timestamp:   time.Now().Unix(),
			nonce:       validNonce,
			adminKey:    s.AdminKey,
			expectCode:  http.StatusUnauthorized,
			expectError: "Nonce Already Used",
		},
		{
			name:        "wrong admin key",
			timestamp:   time.Now().Unix(),
			adminKey:    "wrong-admin",
			expectCode:  http.StatusUnauthorized,
			expectError: "Unauthorized Access",
		},
	}

	for idx, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if idx == 3 {
				// nonce replay sector: first request should be accepted
				firstReq := makeSignedWebhookRequest(t, body, accessKey, secret, s.AdminKey, time.Now().Unix(), validNonce)
				firstRR := httptest.NewRecorder()
				http.HandlerFunc(s.WebhookHandler).ServeHTTP(firstRR, firstReq)
				if firstRR.Code != http.StatusOK {
					t.Fatalf("first request expected ok, got %d: %s", firstRR.Code, firstRR.Body.String())
				}
			}

			var req *http.Request
			if tc.signature != "" {
				req = httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
				req.Header.Set("X-Access-Key", accessKey)
				req.Header.Set("X-Timestamp", fmt.Sprintf("%d", tc.timestamp))
				req.Header.Set("X-Nonce", tc.nonce)
				req.Header.Set("X-Signature", tc.signature)
				req.Header.Set("X-Admin-Key", tc.adminKey)
			} else {
				req = makeSignedWebhookRequest(t, body, accessKey, secret, tc.adminKey, tc.timestamp, tc.nonce)
			}

			rr := httptest.NewRecorder()
			http.HandlerFunc(s.WebhookHandler).ServeHTTP(rr, req)

			if rr.Code != tc.expectCode {
				t.Fatalf("expected status %d, got %d, body=%q", tc.expectCode, rr.Code, rr.Body.String())
			}
			if tc.expectError != "" && !strings.Contains(rr.Body.String(), tc.expectError) {
				t.Fatalf("expected error %q, got body=%q", tc.expectError, rr.Body.String())
			}
		})
	}
}

func TestWebhookHandler_NoNonceReplay(t *testing.T) {
	s := NewServer(":0", nil)
	accessKey := "replay-access"
	secret := "replay-secret"
	s.SetSecretKey(accessKey, secret)
	s.AdminKey = "admin-secret"

	body := []byte(`{"user":"Alice","asset":"Gold","amount":10}`)
	nonce, err := client.GenerateNonce(16)
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}
	ts := time.Now().Unix()

	firstReq := makeSignedWebhookRequest(t, body, accessKey, secret, s.AdminKey, ts, nonce)
	firstRR := httptest.NewRecorder()
	http.HandlerFunc(s.WebhookHandler).ServeHTTP(firstRR, firstReq)
	if firstRR.Code != http.StatusOK {
		t.Fatalf("first request expected 200 OK, got %d, body=%q", firstRR.Code, firstRR.Body.String())
	}

	secondReq := makeSignedWebhookRequest(t, body, accessKey, secret, s.AdminKey, ts, nonce)
	secondRR := httptest.NewRecorder()
	http.HandlerFunc(s.WebhookHandler).ServeHTTP(secondRR, secondReq)
	if secondRR.Code != http.StatusUnauthorized {
		t.Fatalf("second replay request expected 401 Unauthorized, got %d, body=%q", secondRR.Code, secondRR.Body.String())
	}
	if !strings.Contains(secondRR.Body.String(), "Nonce Already Used") {
		t.Fatalf("expected nonce replay error, got body=%q", secondRR.Body.String())
	}
}

func TestModifyUserBalanceScenarios(t *testing.T) {
	type scenario struct {
		name            string
		userName        string
		initialBalances map[string]string
		asset           string
		amount          float64
		wantOK          bool
		wantBalance     string
	}

	scenarios := []scenario{
		{
			name:            "deposit new asset",
			userName:        "Alice",
			initialBalances: map[string]string{},
			asset:           "Gold",
			amount:          10,
			wantOK:          true,
			wantBalance:     "10.00",
		},
		{
			name:            "deposit existing asset",
			userName:        "Alice",
			initialBalances: map[string]string{"Gold": "5.00"},
			asset:           "Gold",
			amount:          5,
			wantOK:          true,
			wantBalance:     "10.00",
		},
		{
			name:            "withdraw within balance",
			userName:        "Alice",
			initialBalances: map[string]string{"Gold": "10.00"},
			asset:           "Gold",
			amount:          -5,
			wantOK:          true,
			wantBalance:     "5.00",
		},
		{
			name:            "withdraw exact balance",
			userName:        "Alice",
			initialBalances: map[string]string{"Gold": "10.00"},
			asset:           "Gold",
			amount:          -10,
			wantOK:          true,
			wantBalance:     "0.00",
		},
		{
			name:            "withdraw over balance",
			userName:        "Alice",
			initialBalances: map[string]string{"Gold": "10.00"},
			asset:           "Gold",
			amount:          -15,
			wantOK:          false,
		},
		{
			name:            "user not found",
			userName:        "Bob",
			initialBalances: nil,
			asset:           "Gold",
			amount:          10,
			wantOK:          false,
		},
	}

	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer(":0", nil)
			if tc.userName == "Bob" {
				s.Users = []User{{Name: "Alice", Balances: tc.initialBalances}}
			} else {
				s.Users = []User{{Name: tc.userName, Balances: tc.initialBalances}}
			}
			w := httptest.NewRecorder()

			amountStr := fmt.Sprintf("%.2f", tc.amount)
			ok := s.ModifyUserBalance(tc.userName, tc.asset, amountStr, w)
			if ok != tc.wantOK {
				t.Fatalf("expected ok=%v, got %v, body=%q", tc.wantOK, ok, w.Body.String())
			}

			if tc.wantOK {
				user, exists := s.GetUser(tc.userName)
				if !exists {
					t.Fatalf("expected user %q to exist", tc.userName)
				}
				gotBalance := user.Balances[tc.asset]
				if gotBalance != tc.wantBalance {
					t.Fatalf("expected balance %q, got %q", tc.wantBalance, gotBalance)
				}
			}
		})
	}
}

func TestGenerateRequestID_Unique(t *testing.T) {
	s := NewServer(":0", nil)
	id1 := s.GenerateRequestID()
	id2 := s.GenerateRequestID()

	if id1 == "" || id2 == "" {
		t.Fatal("expected non-empty request IDs")
	}
	if id1 == id2 {
		t.Fatalf("expected unique request IDs, got %q and %q", id1, id2)
	}
}

func TestLoggingMiddleware_EmitsTelemetryAndRequestID(t *testing.T) {
	s := NewServer(":0", nil)
	var buf bytes.Buffer
	s.Logger = *slog.New(slog.NewJSONHandler(&buf, nil))

	h := s.LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:1234"

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d", rr.Code)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 log lines, got %d: %s", len(lines), buf.String())
	}

	var startLog, endLog map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &startLog); err != nil {
		t.Fatalf("failed to parse first log line: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &endLog); err != nil {
		t.Fatalf("failed to parse second log line: %v", err)
	}

	requestIDStart, ok := startLog["request_id"].(string)
	if !ok || requestIDStart == "" {
		t.Fatalf("expected request_id in start log, got %#v", startLog["request_id"])
	}
	requestIDEnd, ok := endLog["request_id"].(string)
	if !ok || requestIDEnd == "" {
		t.Fatalf("expected request_id in end log, got %#v", endLog["request_id"])
	}
	if requestIDStart != requestIDEnd {
		t.Fatalf("expected same request_id across logs, got %q and %q", requestIDStart, requestIDEnd)
	}

	if startLog["method"] != "GET" {
		t.Fatalf("expected method GET in start log, got %#v", startLog["method"])
	}
	if startLog["path"] != "/test" {
		t.Fatalf("expected path /test in start log, got %#v", startLog["path"])
	}

	status, ok := endLog["status"].(float64)
	if !ok || int(status) != http.StatusAccepted {
		t.Fatalf("expected status 202 in end log, got %#v", endLog["status"])
	}
	if _, ok := endLog["duration_ms"].(float64); !ok {
		t.Fatalf("expected duration_ms in end log, got %#v", endLog["duration_ms"])
	}
}

func TestLogRequestError_IncludesRequestIDAndError(t *testing.T) {
	s := NewServer(":0", nil)
	var buf bytes.Buffer
	s.Logger = *slog.New(slog.NewJSONHandler(&buf, nil))

	req := httptest.NewRequest("GET", "/error", nil)
	requestID := s.GenerateRequestID()
	s.LogRequestError(req, requestID, "failure occurred", http.StatusInternalServerError, fmt.Errorf("boom"))

	line := strings.TrimSpace(buf.String())
	var errLog map[string]any
	if err := json.Unmarshal([]byte(line), &errLog); err != nil {
		t.Fatalf("failed to parse error log: %v", err)
	}

	if errLog["request_id"] != requestID {
		t.Fatalf("expected request_id %q, got %#v", requestID, errLog["request_id"])
	}
	if errLog["status"] != float64(http.StatusInternalServerError) {
		t.Fatalf("expected status 500, got %#v", errLog["status"])
	}
	if errLog["error"] != "boom" {
		t.Fatalf("expected error boom, got %#v", errLog["error"])
	}
}

func TestInitSecretKeyOnce_Concurrent(t *testing.T) {
	s := NewServer(":0", nil)
	const accessKey = "test-access"
	const secret = "secret123"
	var wg sync.WaitGroup
	errs := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.InitSecretKeyOnce(accessKey, secret)
			got, ok := s.GetSecretKey(accessKey)
			if !ok {
				errs <- fmt.Errorf("expected access key to exist")
				return
			}
			if got != secret {
				errs <- fmt.Errorf("expected secret %q, got %q", secret, got)
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatal(err)
	}
}

func TestGetAllUsersReturnsDeepCopy(t *testing.T) {
	s := NewServer(":0", nil)
	s.Users = []User{{Name: "Alice", Balances: map[string]string{"Gold": "10.00"}}}

	users := s.GetAllUsers()
	users[0].Balances["Gold"] = "0.00"

	if s.Users[0].Balances["Gold"] != "10.00" {
		t.Fatalf("expected original user balance to remain 10.00, got %q", s.Users[0].Balances["Gold"])
	}
}

func TestGetUserReturnsDeepCopy(t *testing.T) {
	s := NewServer(":0", nil)
	s.Users = []User{{Name: "Alice", Balances: map[string]string{"Gold": "10.00"}}}

	user, ok := s.GetUser("Alice")
	if !ok {
		t.Fatal("expected user Alice to exist")
	}

	user.Balances["Gold"] = "0.00"

	orig, ok := s.GetUser("Alice")
	if !ok {
		t.Fatal("expected original user Alice to still exist")
	}
	if orig.Balances["Gold"] != "10.00" {
		t.Fatalf("expected original balance to remain 10.00, got %q", orig.Balances["Gold"])
	}
}

func TestGetAllUsersConcurrentReadDuringUpdate(t *testing.T) {
	s := NewServer(":0", nil)
	s.Users = []User{{Name: "Alice", Balances: map[string]string{"Gold": "0.00"}}}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = s.GetAllUsers()
			}
		}()
	}

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = s.ModifyUserBalance("Alice", "Gold", "1.00", httptest.NewRecorder())
			}
		}()
	}

	wg.Wait()
	user, ok := s.GetUser("Alice")
	if !ok {
		t.Fatal("expected user Alice to exist")
	}
	if user.Balances["Gold"] == "0.00" {
		t.Fatal("expected balance to be updated by concurrent writes")
	}
}
