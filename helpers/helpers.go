package helpers

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"reflect"
)

type Credentials struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	AdminKey  string `json:"admin_key"`
}

func generateNonce(length int) (string, error) {
	b := make([]byte, length)

	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func GenerateApiInitialCredentials() *Credentials {
	nonce, err := generateNonce(16)
	if err != nil {
		panic("Failed to generate nonce: " + err.Error())
	}

	creds := &Credentials{
		AccessKey: os.Getenv("ACCESS_KEY"),
		SecretKey: os.Getenv("SECRET_KEY"),
		AdminKey:  os.Getenv("ADMIN_KEY"),
	}

	v := reflect.ValueOf(creds).Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if field.Kind() == reflect.String && field.String() == "" {
			field.SetString(nonce)
		}
	}

	return creds
}
