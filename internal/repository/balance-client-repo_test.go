package repository

import (
	"context"
	"testing"

	protocol "github.com/distuurbia/balance/protocol/balance"
	"github.com/distuurbia/balance/protocol/balance/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAddBalanceChange(t *testing.T) {
	client := new(mocks.BalanceServiceClient)
	client.On("AddBalanceChange", mock.Anything, mock.Anything).Return(nil, nil)
	r := NewBalanceClientRepository(client)

	err := r.AddBalanceChange(context.Background(), uuid.New(), float64(50))
	require.NoError(t, err)
}

func TestGetBalance(t *testing.T) {
	client := new(mocks.BalanceServiceClient)
	client.On("GetBalance", mock.Anything, mock.Anything).Return(&protocol.GetBalanceResponse{TotalBalance: float64(505.3)}, nil)
	r := NewBalanceClientRepository(client)

	totalBalance, err := r.GetBalance(context.Background(), uuid.New())
	require.NoError(t, err)
	require.Equal(t, float64(505.3), totalBalance)
}

func TestDeleteProfilesBalance(t *testing.T) {
	client := new(mocks.BalanceServiceClient)
	client.On("DeleteProfilesBalance", mock.Anything, mock.Anything).Return(nil, nil)
	r := NewBalanceClientRepository(client)

	err := r.DeleteProfilesBalance(context.Background(), uuid.New())
	require.NoError(t, err)
}
