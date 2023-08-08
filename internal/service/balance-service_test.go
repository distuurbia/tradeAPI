package service

import (
	"context"
	"testing"

	"github.com/distuurbia/tradeAPI/internal/service/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAddBalanceChange(t *testing.T) {
	r := new(mocks.BalanceClientRepository)
	r.On("AddBalanceChange", mock.Anything, mock.AnythingOfType("uuid.UUID"), mock.AnythingOfType("float64")).Return(nil)

	s := NewBalanceService(r)
	err := s.AddBalanceChange(context.Background(), uuid.New(), float64(505.2))
	require.NoError(t, err)
}

func TestGetBalance(t *testing.T) {
	r := new(mocks.BalanceClientRepository)
	r.On("GetBalance", mock.Anything, mock.AnythingOfType("uuid.UUID")).Return(float64(502.6), nil)

	s := NewBalanceService(r)
	totalAmount, err := s.GetBalance(context.Background(), uuid.New())

	require.NoError(t, err)
	require.Equal(t, float64(502.6), totalAmount)
}

func TestDeleteProfilesBalance(t *testing.T) {
	r := new(mocks.BalanceClientRepository)
	r.On("DeleteProfilesBalance", mock.Anything, mock.AnythingOfType("uuid.UUID")).Return(nil)

	s := NewBalanceService(r)
	err := s.DeleteProfilesBalance(context.Background(), uuid.New())
	require.NoError(t, err)
}
