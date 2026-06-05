package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
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

func (s *Server) logError(w http.ResponseWriter, message string, statusCode int) {
	s.Logger.Error(message, "error", statusCode)
	http.Error(w, message, statusCode)
}

func (s *Server) WebhookHandler(w http.ResponseWriter, r *http.Request) {
	i := Input{}

	if !s.validateHeaders(r) {
		return
	}

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
}

// Admin Endpoint only
func (s *Server) NonceHandler(w http.ResponseWriter, r *http.Request) {
	errMsg := "Invalid HTTP Method"

	r.Header.Set("Content-Type", "application/json")

	if !s.ValidateAdminAccess(s.AdminKey, r) {
		s.logError(w, "Unauthorized Access", http.StatusUnauthorized)
		return
	}

	if !s.validateHeaders(r) {
		return
	}

	if !s.CheckHTTPMethod(r, "GET") {
		s.logError(w, errMsg, http.StatusMethodNotAllowed)
		return
	}

	json.NewEncoder(w).Encode(s.NonceVault.Nonces)
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
