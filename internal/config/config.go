// Package config represents struct Config.
package config

// Config is a structure of environment variables.
type Config struct {
	PostgresPath string `env:"POSTGRES_PATH"`
	SecretKey    string `env:"SECRET_KEY"`
}
