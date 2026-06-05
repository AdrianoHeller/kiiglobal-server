package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
	req := httptest.NewRequest("GET", "/webhook", bytes.NewReader(body))
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
	req := httptest.NewRequest("GET", "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Access-Key", "test-access")
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	req.Header.Set("X-Admin-Key", s.AdminKey)

	rr := httptest.NewRecorder()
	http.HandlerFunc(s.WebhookHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d, body=%s", rr.Code, rr.Body.String())
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

	req := httptest.NewRequest("GET", "/webhook", bytes.NewReader(body))
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
				req = httptest.NewRequest("GET", "/webhook", bytes.NewReader(body))
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

			ok := s.ModifyUserBalance(tc.userName, tc.asset, tc.amount, w)
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
