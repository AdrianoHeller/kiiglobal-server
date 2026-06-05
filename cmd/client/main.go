package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"

	"github.com/AdrianoHeller/kii/client"
)

func main() {
	accessKey := os.Getenv("ACCESS_KEY")
	secretKey := os.Getenv("SECRET_KEY")
	serverUrl := os.Getenv("SERVER_URL")

	if accessKey == "" || secretKey == "" {
		fmt.Println("ACCESS_KEY and SECRET_KEY must be set in the environment")
		return
	}

	if serverUrl == "" {
		fmt.Println("SERVER_URL must be set in the environment")
		return
	}

	hmacClient := client.NewClient(accessKey, secretKey)

	reqBody := []byte(`{
		"user":   "John Wick",
		"asset":  "Continental",
		"amount": 100.00,
	}`)

	serverUrl = fmt.Sprintf("%s/webhook", serverUrl)

	req, err := http.NewRequest("POST", serverUrl, bytes.NewReader(reqBody))
	if err != nil {
		fmt.Printf("Failed to create request: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	response, err := hmacClient.DoRequest(req)
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		return
	}
	defer response.Body.Close()

	fmt.Printf("Response status: %s\n", response.Status)
}
