package repository

import (
	"os"
	"testing"

	"github.com/distuurbia/tradeAPI/internal/model"
	"github.com/google/uuid"
)

var (
	testProfile = model.Profile{
		ID:           uuid.New(),
		Password:     []byte("password"),
		RefreshToken: []byte("refreshToken"),
		Username:     "Volodya",
		Country:      "Belarus",
		Age:          27,
	}
)

func TestMain(m *testing.M) {
	exitCode := m.Run()
	os.Exit(exitCode)
}
