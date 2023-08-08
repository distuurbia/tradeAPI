package handler

import (
	"os"
	"testing"

	"github.com/distuurbia/tradeAPI/internal/model"
	"github.com/go-playground/validator"
)

var (
	validate *validator.Validate

	testSignUpRequest = model.SignUpRequest{
		Password: "password",
		Username: "Volodya",
		Country:  "Belarus",
		Age:      27,
	}

	testLoginRequest = model.LoginRequest{
		Username: "Vladimir",
		Password: "12345",
	}

	testTokenPair = model.TokenPair{
		AccessToken:  "oldAccessToken",
		RefreshToken: "oldRefreshToken",
	}
)

func TestMain(m *testing.M) {
	validate = validator.New()
	exitCode := m.Run()
	os.Exit(exitCode)
}
