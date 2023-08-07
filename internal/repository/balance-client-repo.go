// Package repository contains calls methods of other microservices
package repository

import (
	"context"
	"fmt"

	protocol "github.com/distuurbia/balance/protocol/balance"
	"github.com/google/uuid"
)

// BalanceClientRepository contains ProfileServiceClient
type BalanceClientRepository struct {
	client protocol.BalanceServiceClient
}

// NewBalanceClientRepository creates an object of *BalanceClientRepository
func NewBalanceClientRepository(client protocol.BalanceServiceClient) *BalanceClientRepository {
	return &BalanceClientRepository{client: client}
}

// AddBalanceChange calls method AddBalanceChange from balance microservice
func (r *BalanceClientRepository) AddBalanceChange(ctx context.Context, profileID uuid.UUID, amount float64) error {
	_, err := r.client.AddBalanceChange(ctx, &protocol.AddBalanceChangeRequest{ProfileID: profileID.String(), Amount: amount})
	if err != nil {
		return fmt.Errorf("BalanceClientRepository -> AddBalanceChange -> %w", err)
	}
	return nil
}

// GetBalance calls method GetBalance from balance microservice
func (r *BalanceClientRepository) GetBalance(ctx context.Context, profileID uuid.UUID) (float64, error) {
	resp, err := r.client.GetBalance(ctx, &protocol.GetBalanceRequest{ProfileID: profileID.String()})
	if err != nil {
		return float64(0), fmt.Errorf("BalanceClientRepository -> GetBalance -> %w", err)
	}
	return resp.TotalBalance, nil
}

// DeleteProfilesBalance calls method DeleteProfilesBalance from balance microservice
func (r *BalanceClientRepository) DeleteProfilesBalance(ctx context.Context, profileID uuid.UUID) error {
	_, err := r.client.DeleteProfilesBalance(ctx, &protocol.DeleteProfilesBalanceRequest{ProfileID: profileID.String()})
	if err != nil {
		return fmt.Errorf("BalanceClientRepository -> DeleteProfilesBalance -> %w", err)
	}
	return nil
}