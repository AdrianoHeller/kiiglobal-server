package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

type Vault struct {
	Mu          sync.RWMutex
	Credentials map[string]string
}

type NonceVault struct {
	Mu     sync.RWMutex
	Nonces map[string]time.Time
}

type Input struct {
	User   string  `json:"user"`
	Asset  string  `json:"asset"`
	Amount float64 `json:"amount"`
}

type User struct {
	Name     string            `json:"user"`
	Balances map[string]string `json:"balances"`
}

type Server struct {
	Server     *http.Server
	Logger     slog.Logger
	Vault      *Vault
	NonceVault *NonceVault
	Users      []User
	AdminKey   string
}

func NewServer(port string, handler http.Handler) *Server {
	return &Server{
		Server: &http.Server{
			Addr:         port,
			Handler:      handler,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		Logger: *slog.New(slog.NewJSONHandler(os.Stdout, nil)),
		Vault: &Vault{
			Credentials: make(map[string]string),
		},
		NonceVault: &NonceVault{
			Nonces: make(map[string]time.Time),
		},
		AdminKey: os.Getenv("ADMIN_KEY"),
	}
}

// HTTP functions
func (s *Server) ValidateAdminAccess(key string, r *http.Request) bool {
	adminKey := r.Header.Get("X-Admin-Key")
	return adminKey == s.AdminKey && key != ""
}

func (s *Server) validateHeaders(req *http.Request) bool {

	signature := req.Header.Get("X-Signature")
	nonce := req.Header.Get("X-Nonce")

	// Missing Signature or Nonce
	if signature == "" || nonce == "" {
		s.Logger.Error("Empty Validation Data", "error", http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *Server) CheckHTTPMethod(req *http.Request, method string) bool {
	if req.Method != method {
		return false
	}
	return true
}

// Vault Functions
func (s *Server) SetSecretKey(accessKey, secretKey string) {

	s.Vault.Mu.Lock()
	defer s.Vault.Mu.Unlock()

	s.Vault.Credentials[accessKey] = secretKey
}

func (s *Server) GetSecretKey(accessKey string) (string, bool) {

	s.Vault.Mu.RLock()
	defer s.Vault.Mu.RUnlock()

	secretKey, exists := s.Vault.Credentials[accessKey]
	return secretKey, exists
}

// Hashing functions
func (s *Server) ComputeHmacSignature(timestamp int64, body []byte, nonce, secretKey string) string {
	bodyHash := sha256.New()
	bodyHash.Write(body)
	bodyHashString := hex.EncodeToString(bodyHash.Sum(nil))

	buildCanonicalString := fmt.Sprintf("%d\n%s\n%s", timestamp, nonce, bodyHashString)

	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(buildCanonicalString))

	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) logError(w http.ResponseWriter, message string, statusCode int) {
	s.Logger.Error(message, "error", statusCode)
	http.Error(w, message, statusCode)
}

func (s *Server) TimestampValidation(timestampStr string) bool {
	ts, err := strconv.ParseInt(timestampStr, 10, 64)

	if err != nil {
		s.Logger.Error("Invalid Timestamp Format", "error", err)
		return false
	}

	requestTime := time.Unix(ts, 0)

	age := time.Since(requestTime)

	// Parse TIMESTAMP_AGE from environment as a duration (e.g. "5m", "30s").
	// Fallback to 5 minutes when not set or invalid.
	windowStr := os.Getenv("TIMESTAMP_AGE")
	var feasibleWindow time.Duration
	if windowStr == "" {
		feasibleWindow = 5 * time.Minute
	} else {
		d, err := time.ParseDuration(windowStr)
		if err != nil {
			s.Logger.Error("Invalid TIMESTAMP_AGE format", "error", err)
			feasibleWindow = 5 * time.Minute
		} else {
			feasibleWindow = d
		}
	}

	if age > feasibleWindow {
		s.Logger.Error("Request Too Old", "age", age)
		return false
	}

	return true
}

func (s *Server) WebhookHandler(w http.ResponseWriter, r *http.Request) {

	//Get Access Key from Header
	accessKey := r.Header.Get("X-Access-Key")
	// Get Timestamp and Nonce from Headers
	timestamp := r.Header.Get("X-Timestamp")
	nonce := r.Header.Get("X-Nonce")

	//Get Secret Key from Vault
	secretKey, exists := s.GetSecretKey(accessKey)

	if !exists {
		s.logError(w, "Invalid Access Key", http.StatusUnauthorized)
		return
	}

	s.Logger.Info("Received Webhook Request", "access_key", accessKey)

	r.Header.Set("Content-Type", "application/json")

	if !s.ValidateAdminAccess(s.AdminKey, r) {
		s.logError(w, "Unauthorized Access", http.StatusUnauthorized)
		return
	}

	if !s.validateHeaders(r) {
		return
	}

	if !s.TimestampValidation(timestamp) {
		s.logError(w, "Invalid or expired timestamp", http.StatusUnauthorized)
		return
	}

	if !s.CheckHTTPMethod(r, "GET") {
		s.logError(w, "Invalid HTTP Method", http.StatusMethodNotAllowed)
		return
	}

	i := Input{}

	body, err := io.ReadAll(r.Body)

	if err := json.Unmarshal(body, &i); err != nil {
		s.logError(w, "Error parsing request body", http.StatusBadRequest)
		return
	}

	if err != nil {
		s.logError(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	r.Header.Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(i)

	r.Body = io.NopCloser(bytes.NewReader(body))

	s.Logger.Info("Processed Webhook Request", "user", i.User, "asset", i.Asset, "amount", i.Amount)

	expectedSignature := s.ComputeHmacSignature(time.Now().Unix(), body, nonce, secretKey)

	if expectedSignature != r.Header.Get("X-Signature") {
		s.logError(w, "Invalid Signature", http.StatusUnauthorized)
		return
	}

	s.Logger.Info("Valid Webhook Request", "user", i.User, "asset", i.Asset, "amount", i.Amount)
}

// Admin Endpoint only
func (s *Server) UserHandler(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("Content-Type", "application/json")

	if !s.ValidateAdminAccess(s.AdminKey, r) {
		s.logError(w, "Unauthorized Access", http.StatusUnauthorized)
		return
	}

	if !s.validateHeaders(r) {
		return
	}

	if !s.CheckHTTPMethod(r, "GET") {
		s.logError(w, "Invalid HTTP Method", http.StatusMethodNotAllowed)
		return
	}

	json.NewEncoder(w).Encode(s.Users)
}

// NonceHandler returns the stored nonces (admin-only)
func (s *Server) NonceHandler(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("Content-Type", "application/json")

	if !s.ValidateAdminAccess(s.AdminKey, r) {
		s.logError(w, "Unauthorized Access", http.StatusUnauthorized)
		return
	}

	if !s.validateHeaders(r) {
		return
	}

	if !s.CheckHTTPMethod(r, "GET") {
		s.logError(w, "Invalid HTTP Method", http.StatusMethodNotAllowed)
		return
	}

	s.NonceVault.Mu.RLock()
	defer s.NonceVault.Mu.RUnlock()

	json.NewEncoder(w).Encode(s.NonceVault.Nonces)
}
