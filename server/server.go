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
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
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
	User   string      `json:"user"`
	Asset  string      `json:"asset"`
	Amount json.Number `json:"amount"`
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

func (s *Server) validateHeaders(w http.ResponseWriter, req *http.Request) bool {

	signature := req.Header.Get("X-Signature")
	nonce := req.Header.Get("X-Nonce")

	if signature == "" || nonce == "" {
		s.logError(w, "Missing signature or nonce", http.StatusUnauthorized)
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

func (s *Server) AddNonceFromRequest(nonce string) {

	s.NonceVault.Mu.Lock()
	defer s.NonceVault.Mu.Unlock()

	s.NonceVault.Nonces[nonce] = time.Now()
}

func (s *Server) CheckNonce(nonce string) bool {

	s.NonceVault.Mu.RLock()
	defer s.NonceVault.Mu.RUnlock()

	if _, exists := s.NonceVault.Nonces[nonce]; exists {
		return false
	}
	return true
}

func (s *Server) GetSecretKey(accessKey string) (string, bool) {

	s.Vault.Mu.RLock()
	defer s.Vault.Mu.RUnlock()

	secretKey, exists := s.Vault.Credentials[accessKey]
	return secretKey, exists
}

func parseDecimal(value string) (*big.Float, error) {
	f, ok := new(big.Float).SetPrec(128).SetMode(big.ToNearestEven).SetString(value)
	if !ok {
		return nil, fmt.Errorf("invalid decimal value: %q", value)
	}
	return f, nil
}

func formatDecimal(value *big.Float) string {
	return value.Text('f', 2)
}

func addDecimals(a, b string) (string, error) {
	aFloat, err := parseDecimal(a)
	if err != nil {
		return "", err
	}
	bFloat, err := parseDecimal(b)
	if err != nil {
		return "", err
	}
	result := new(big.Float).SetPrec(128).SetMode(big.ToNearestEven)
	result.Add(aFloat, bFloat)
	return formatDecimal(result), nil
}

func compareDecimals(a, b string) (int, error) {
	aFloat, err := parseDecimal(a)
	if err != nil {
		return 0, err
	}
	bFloat, err := parseDecimal(b)
	if err != nil {
		return 0, err
	}
	return aFloat.Cmp(bFloat), nil
}

func (s *Server) CheckUser(user User) {

	s.Vault.Mu.Lock()
	defer s.Vault.Mu.Unlock()
	for _, u := range s.Users {
		if u.Name == user.Name {
			return
		}
	}
	// If user doesn't exist, add to the list
	s.Users = append(s.Users, user)
}

func (s *Server) GetUser(name string) (User, bool) {

	s.Vault.Mu.RLock()
	defer s.Vault.Mu.RUnlock()

	for _, u := range s.Users {
		if u.Name == name {
			return u, true
		}
	}
	return User{}, false
}

func (s *Server) GetAllUsers() []User {
	s.Vault.Mu.RLock()
	defer s.Vault.Mu.RUnlock()

	return s.Users
}

func (s *Server) ModifyUserBalance(userName, asset, amountStr string, w http.ResponseWriter) bool {

	s.Vault.Mu.Lock()
	defer s.Vault.Mu.Unlock()
	for i, u := range s.Users {
		if u.Name == userName {
			if u.Balances == nil {
				s.Users[i].Balances = make(map[string]string)
			}
			currentBalanceStr, exists := u.Balances[asset]
			if !exists {
				currentBalanceStr = "0.00"
			}

			newBalance, err := addDecimals(currentBalanceStr, amountStr)
			if err != nil {
				s.logError(w, "Invalid amount or balance format", http.StatusBadRequest)
				return false
			}

			if cmp, err := compareDecimals(newBalance, "0.00"); err != nil {
				s.logError(w, "Invalid balance calculation", http.StatusInternalServerError)
				return false
			} else if cmp < 0 {
				s.logError(w, fmt.Sprintf("Invalid balance in the %s for the User to perform the transaction", asset), http.StatusBadRequest)
				return false
			}

			s.Users[i].Balances[asset] = newBalance
			return true
		}
	}
	return false
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

	//Check if credentials vault are empty
	if len(s.Vault.Credentials) == 0 {
		// For the first run as testing purposes, we will set the secret key in the vault directly from environment variables. In production, this should be set through a secure admin endpoint and stored in a secure vault.
		s.SetSecretKey(accessKey, os.Getenv("SECRET_KEY"))
	}

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

	if !s.validateHeaders(w, r) {
		return
	}

	if !s.TimestampValidation(timestamp) {
		s.logError(w, "Invalid or expired timestamp", http.StatusUnauthorized)
		return
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		s.logError(w, "Invalid Timestamp", http.StatusBadRequest)
		return
	}

	if !s.CheckHTTPMethod(r, "GET") {
		s.logError(w, "Invalid HTTP Method", http.StatusMethodNotAllowed)
		return
	}

	if !s.CheckNonce(nonce) {
		s.logError(w, "Nonce Already Used", http.StatusUnauthorized)
		return
	}

	s.AddNonceFromRequest(nonce)

	i := Input{}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logError(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	if err := json.Unmarshal(body, &i); err != nil {
		s.logError(w, "Error parsing request body", http.StatusBadRequest)
		return
	}

	if i.User == "" || i.Asset == "" || i.Amount == "" {
		s.logError(w, "Missing request payload fields", http.StatusBadRequest)
		return
	}

	amountStr := i.Amount.String()
	if _, err := parseDecimal(amountStr); err != nil {
		s.logError(w, "Invalid amount format", http.StatusBadRequest)
		return
	}

	expectedSignature := s.ComputeHmacSignature(ts, body, nonce, secretKey)

	if expectedSignature != r.Header.Get("X-Signature") {
		s.logError(w, "Invalid Signature", http.StatusUnauthorized)
		return
	}

	r.Header.Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(i)

	r.Body = io.NopCloser(bytes.NewReader(body))

	s.Logger.Info("Processed Webhook Request", "user", i.User, "asset", i.Asset, "amount", i.Amount)
	s.Logger.Info("Valid Webhook Request", "user", i.User, "asset", i.Asset, "amount", i.Amount)

	s.CheckUser(User{Name: i.User, Balances: map[string]string{}})

	s.ModifyUserBalance(i.User, i.Asset, amountStr, w)
}

// Admin Endpoint only
func (s *Server) UserHandler(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("Content-Type", "application/json")

	if !s.ValidateAdminAccess(s.AdminKey, r) {
		s.logError(w, "Unauthorized Access", http.StatusUnauthorized)
		return
	}

	if !s.validateHeaders(w, r) {
		return
	}

	if !s.CheckHTTPMethod(r, "GET") {
		s.logError(w, "Invalid HTTP Method", http.StatusMethodNotAllowed)
		return
	}

	json.NewEncoder(w).Encode(s.Users)
}

func (s *Server) UserDetailHandler(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("Content-Type", "application/json")

	if !s.ValidateAdminAccess(s.AdminKey, r) {
		s.logError(w, "Unauthorized Access", http.StatusUnauthorized)
		return
	}

	if !s.validateHeaders(w, r) {
		return
	}

	if !s.CheckHTTPMethod(r, "GET") {
		s.logError(w, "Invalid HTTP Method", http.StatusMethodNotAllowed)
		return
	}

	pathPrefix := "/balance/"
	if !strings.HasPrefix(r.URL.Path, pathPrefix) {
		s.logError(w, "Invalid user path", http.StatusBadRequest)
		return
	}

	userName := strings.TrimPrefix(r.URL.Path, pathPrefix)
	if userName == "" {
		s.logError(w, "Missing user name", http.StatusBadRequest)
		return
	}

	user, found := s.GetUser(userName)
	if !found {
		s.logError(w, "User not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(user)
}

// NonceHandler returns the stored nonces (admin-only)
func (s *Server) NonceHandler(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("Content-Type", "application/json")

	if !s.ValidateAdminAccess(s.AdminKey, r) {
		s.logError(w, "Unauthorized Access", http.StatusUnauthorized)
		return
	}

	if !s.validateHeaders(w, r) {
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
