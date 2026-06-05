package main

import (
	"net/http"
	"os"

	"github.com/AdrianoHeller/kii/server"
)

func main() {

	serverPort := os.Getenv("SERVER_PORT")
	serverPort = ":" + serverPort

	if serverPort == "" {
		serverPort = ":5001"
	}

	mux := http.NewServeMux()

	s := server.NewServer(serverPort, mux)

	// If ACCESS_KEY and SECRET_KEY are provided in the environment, register
	// them in the server's in-memory vault so incoming requests from the
	// local `cmd/client` can be validated.
	accessKey := os.Getenv("ACCESS_KEY")
	secretKey := os.Getenv("SECRET_KEY")
	if accessKey != "" && secretKey != "" {
		s.SetSecretKey(accessKey, secretKey)
	}

	//Public Endpoints
	mux.HandleFunc("/webhook", s.WebhookHandler)

	//Admin Endpoints
	mux.HandleFunc("/nonces", s.NonceHandler)
	mux.HandleFunc("/users", s.UserHandler)
	mux.HandleFunc("/balance/", s.UserDetailHandler)
	mux.HandleFunc("/ledger", s.LedgerHandler)

	s.Logger.Info("Server Running")

	err := s.Server.ListenAndServe()

	if err != nil {
		s.Logger.Error("Error Running Server", "error", err)
	}
}
