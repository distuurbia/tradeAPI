package repository

import (
	"context"
	"testing"

	protocol "github.com/distuurbia/profile/protocol/profile"
	"github.com/distuurbia/profile/protocol/profile/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCreateProfile(t *testing.T) {
	client := new(mocks.ProfileServiceClient)
	client.On("CreateProfile", mock.Anything, mock.Anything).Return(nil, nil)
	r := NewProfileClientRepository(client)
	err := r.CreateProfile(context.Background(), &testProfile)
	require.NoError(t, err)
}

func TestGetPasswordAndIDByUsername(t *testing.T) {
	client := new(mocks.ProfileServiceClient)
	client.On("GetPasswordAndIDByUsername", mock.Anything, mock.Anything).
		Return(&protocol.GetPasswordAndIDByUsernameResponse{Id: testProfile.ID.String(), Password: testProfile.Password}, nil)

	r := NewProfileClientRepository(client)

	profileID, password, err := r.GetPasswordAndIDByUsername(context.Background(), testProfile.Username)
	require.NoError(t, err)

	require.Equal(t, testProfile.ID, profileID)
	require.Equal(t, testProfile.Password, password)
}

func TestGetRefreshTokenByID(t *testing.T) {
	client := new(mocks.ProfileServiceClient)
	client.On("GetRefreshTokenByID", mock.Anything, mock.Anything).
		Return(&protocol.GetRefreshTokenByIDResponse{HashedRefresh: testProfile.RefreshToken}, nil)

	r := NewProfileClientRepository(client)

	hashedRefresh, err := r.GetRefreshTokenByID(context.Background(), testProfile.ID)
	require.NoError(t, err)

	require.Equal(t, testProfile.RefreshToken, hashedRefresh)
}

func TestAddRefreshToken(t *testing.T) {
	client := new(mocks.ProfileServiceClient)
	client.On("AddRefreshToken", mock.Anything, mock.Anything).
		Return(nil, nil)

	r := NewProfileClientRepository(client)

	err := r.AddRefreshToken(context.Background(), testProfile.RefreshToken, testProfile.ID)
	require.NoError(t, err)
}

func TestDeleteProfile(t *testing.T) {
	client := new(mocks.ProfileServiceClient)
	client.On("DeleteProfile", mock.Anything, mock.Anything).
		Return(nil, nil)

	r := NewProfileClientRepository(client)

	err := r.DeleteProfile(context.Background(), testProfile.ID)
	require.NoError(t, err)
}
