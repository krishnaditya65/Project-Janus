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
}

func Load() Config {
	err := godotenv.Load()
	if err != nil {
		log.Println(".env file not found, using system environment")
	}

	return Config{
		AppEnv:      getEnv("APP_ENV", "development"),
		HTTPPort:    getEnv("HTTP_PORT", "8080"),
		DatabaseURL:     getEnv("DATABASE_URL", ""),
		DatabaseReadURL: getEnv("DATABASE_READ_URL", ""),
		RedisAddr:   getEnv("REDIS_ADDR", "localhost:6380"),
		NATSURL:     getEnv("NATS_URL", "nats://localhost:4223"),
		JWTIssuer:      getEnv("JWT_ISSUER", "http://localhost:8080"),
		WebAuthnRPID:   getEnv("WEBAUTHN_RPID", "localhost"),
		WebAuthnName:   getEnv("WEBAUTHN_NAME", "Auth Server"),
		WebAuthnOrigin: getEnv("WEBAUTHN_ORIGIN", "http://localhost:3000"),
	}
}

func getEnv(key string, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}

	return val
}
