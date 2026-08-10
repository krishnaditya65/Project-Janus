package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	AppEnv          string
	HTTPPort        string
	DatabaseURL     string
	DatabaseReadURL string // optional read-replica DSN; if empty, falls back to DatabaseURL
	RedisAddr       string
	NATSURL         string
	JWTIssuer       string
	WebAuthnRPID    string
	WebAuthnName    string
	WebAuthnOrigin  string

	// IdentityHTTPPort is the port identity-service listens on.
	IdentityHTTPPort string
	// IdentityServiceURL is where other services (iam-server) reach
	// identity-service's internal HTTP API.
	IdentityServiceURL string

	// MFAHTTPPort is the port mfa-service listens on.
	MFAHTTPPort string
	// MFAServiceURL is where other services (iam-server) reach
	// mfa-service's HTTP API (both the principal-authenticated
	// enroll/verify/list/complete/webauthn routes and the internal-only
	// factor/challenge routes backing mfa/infra/httpclient).
	MFAServiceURL string
}

func Load() Config {
	err := godotenv.Load()
	if err != nil {
		log.Println(".env file not found, using system environment")
	}

	return Config{
		AppEnv:          getEnv("APP_ENV", "development"),
		HTTPPort:        getEnv("HTTP_PORT", "8080"),
		DatabaseURL:     getEnv("DATABASE_URL", ""),
		DatabaseReadURL: getEnv("DATABASE_READ_URL", ""),
		RedisAddr:       getEnv("REDIS_ADDR", "localhost:6380"),
		NATSURL:         getEnv("NATS_URL", "nats://localhost:4223"),
		JWTIssuer:       getEnv("JWT_ISSUER", "http://localhost:8080"),
		WebAuthnRPID:    getEnv("WEBAUTHN_RPID", "localhost"),
		WebAuthnName:    getEnv("WEBAUTHN_NAME", "Auth Server"),
		WebAuthnOrigin:  getEnv("WEBAUTHN_ORIGIN", "http://localhost:3000"),

		IdentityHTTPPort:   getEnv("IDENTITY_HTTP_PORT", "8081"),
		IdentityServiceURL: getEnv("IDENTITY_SERVICE_URL", "http://localhost:8081"),

		MFAHTTPPort:   getEnv("MFA_HTTP_PORT", "8082"),
		MFAServiceURL: getEnv("MFA_SERVICE_URL", "http://localhost:8082"),
	}
}

func getEnv(key string, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}
