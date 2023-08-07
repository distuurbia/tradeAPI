// Package repository contains calls methods of other microservices
package repository

import (
	"context"
	"fmt"

	protocol "github.com/distuurbia/profile/protocol/profile"
	"github.com/distuurbia/tradeAPI/internal/model"
	"github.com/google/uuid"
)

// ProfileClientRepository contains ProfileServiceClient
type ProfileClientRepository struct {
	client protocol.ProfileServiceClient
}

// NewProfileClientRepository creates an object of *ProfileClientRepository
func NewProfileClientRepository(client protocol.ProfileServiceClient) *ProfileClientRepository {
	return &ProfileClientRepository{client: client}
}

// CreateProfile calls CreateProfile method of profile microservice
func (r *ProfileClientRepository) CreateProfile(ctx context.Context, profile *model.Profile) error {
	protoProfile := protocol.Profile{
		Id:           profile.ID.String(),
		Username:     profile.Username,
		Password:     profile.Password,
		RefreshToken: profile.RefreshToken,
		Country:      profile.Country,
		Age:          profile.Age,
	}
	_, err := r.client.CreateProfile(ctx, &protocol.CreateProfileRequest{Profile: &protoProfile})
	if err != nil {
		return fmt.Errorf("ProfileClientRepository -> CreateProfile -> %w", err)
	}

	return nil
}

// GetPasswordAndIDByUsername calls GetPasswordAndIDByUsername method of profile microservice
func (r *ProfileClientRepository) GetPasswordAndIDByUsername(ctx context.Context, username string) (uuid.UUID, []byte, error) {
	resp, err := r.client.GetPasswordAndIDByUsername(ctx, &protocol.GetPasswordAndIDByUsernameRequest{Username: username})
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("ProfileClientRepository -> GetPasswordAndIDByUsername: %w", err)
	}
	profileID, err := uuid.Parse(resp.Id)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("ProfileClientRepository -> GetPasswordAndIDByUsername: %w", err)
	}

	return profileID, resp.Password, nil
}

// GetRefreshTokenByID calls GetRefreshTokenByID method of profile microservice
func (r *ProfileClientRepository) GetRefreshTokenByID(ctx context.Context, profileID uuid.UUID) ([]byte, error) {
	resp, err := r.client.GetRefreshTokenByID(ctx, &protocol.GetRefreshTokenByIDRequest{Id: profileID.String()})
	if err != nil {
		return nil, fmt.Errorf("ProfileClientRepository -> GetRefreshTokenByID: %w", err)
	}
	return resp.HashedRefresh, nil
}

// AddRefreshToken calls AddRefreshToken method of profile microservice
func (r *ProfileClientRepository) AddRefreshToken(ctx context.Context, refreshToken []byte, profileID uuid.UUID) error {
	_, err := r.client.AddRefreshToken(ctx, &protocol.AddRefreshTokenRequest{HashedRefresh: refreshToken, Id: profileID.String()})
	if err != nil {
		return fmt.Errorf("ProfileClientRepository -> AddRefreshToken: %w", err)
	}

	return nil
}

// DeleteProfile calls DeleteProfile method of profile microservice
func (r *ProfileClientRepository) DeleteProfile(ctx context.Context, profileID uuid.UUID) error {
	_, err := r.client.DeleteProfile(ctx, &protocol.DeleteProfileRequest{Id: profileID.String()})
	if err != nil {
		return fmt.Errorf("ProfileClientRepository -> DeleteProfile -> error: %w", err)
	}

	return nil
}