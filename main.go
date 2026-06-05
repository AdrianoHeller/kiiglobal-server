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

	//Public Endpoints
	mux.HandleFunc("/webhook", s.WebhookHandler)

	//Admin Endpoints
	mux.HandleFunc("/nonces", s.NonceHandler)
	mux.HandleFunc("/users", s.UserHandler)

	s.Logger.Info("Server Running")

	err := s.Server.ListenAndServe()

	if err != nil {
		s.Logger.Error("Error Running Server", "error", err)
	}
}
