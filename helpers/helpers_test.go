package helpers

import (
	"os"
	"testing"
)

func TestGenerateApiInitialCredentials_Fallback(t *testing.T) {
	os.Unsetenv("ACCESS_KEY")
	os.Unsetenv("SECRET_KEY")
	os.Unsetenv("ADMIN_KEY")

	creds := GenerateApiInitialCredentials()
	if creds.AccessKey == "" || creds.SecretKey == "" || creds.AdminKey == "" {
		t.Fatalf("expected non-empty credential fields, got %+v", creds)
	}
	if creds.AccessKey != creds.SecretKey || creds.AccessKey != creds.AdminKey {
		t.Fatalf("expected all fields to be set to the same nonce, got %+v", creds)
	}
}
