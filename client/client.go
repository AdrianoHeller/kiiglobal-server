package client

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"
)

func hashBody(body []byte) string {
	h := sha256.New()
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func buildCanonicalString(body []byte, nonce string, timestamp int64) string {
	bodyHash := hashBody(body)
	return fmt.Sprintf("%d\n%s\n%s", timestamp, nonce, bodyHash)
}

func GenerateNonce(length int) (string, error) {
	b := make([]byte, length)

	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

type HmacClient struct {
	client    *http.Client
	accessKey string
	secretKey string
}

func NewClient(accessKey, secretKey string) *HmacClient {
	return &HmacClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		accessKey: accessKey,
		secretKey: secretKey,
	}
}

func (c *HmacClient) computeHmac(message string) string {
	mac := hmac.New(sha256.New, []byte(c.secretKey))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func (c *HmacClient) DoRequest(req *http.Request) (*http.Response, error) {

	var body []byte
	var err error

	body, err = io.ReadAll(req.Body)

	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	nonce, err := GenerateNonce(16)

	if err != nil {
		fmt.Println("Error creating nonce:", err)
	}

	timestamp := time.Now().Unix()
	canonicalString := buildCanonicalString(body, nonce, timestamp)
	signature := c.computeHmac(canonicalString)

	req.Header.Set("X-Access-Key", c.accessKey)
	req.Header.Set("X-Signature", signature)

	return c.client.Do(req)
}
