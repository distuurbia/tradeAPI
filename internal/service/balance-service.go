package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// BalanceClientRepository is an interface of repository.BalanceRepository and contains its methods
type BalanceClientRepository interface {
	AddBalanceChange(ctx context.Context, profileID uuid.UUID, amount float64) error
	GetBalance(ctx context.Context, profileID uuid.UUID) (float64, error)
	DeleteProfilesBalance(ctx context.Context, profileID uuid.UUID) error
}

// BalanceService contains an object of ProfileRepository and config with env variables
type BalanceService struct {
	r BalanceClientRepository
}

// NewBalanceService creates *ProfileSevice object filles it and returns
func NewBalanceService(r BalanceClientRepository) *BalanceService {
	return &BalanceService{r: r}
}

// AddBalanceChange calls method AddBalanceChange of repository
func (s *BalanceService) AddBalanceChange(ctx context.Context, profileID uuid.UUID, amount float64) error {
	err := s.r.AddBalanceChange(ctx, profileID, amount)
	if err != nil {
		return fmt.Errorf("BalanceService -> AddBalanceChange -> %w", err)
	}
	return nil
}

// GetBalance calls method GetBalance of repository
func (s *BalanceService) GetBalance(ctx context.Context, profileID uuid.UUID) (float64, error) {
	totalAmount, err := s.r.GetBalance(ctx, profileID)
	if err != nil {
		return float64(0), fmt.Errorf("BalanceService -> GetBalance -> %w", err)
	}
	return totalAmount, nil
}

// DeleteProfilesBalance calls method DeleteProfilesBalance of repository
func (s *BalanceService) DeleteProfilesBalance(ctx context.Context, profileID uuid.UUID) error {
	err := s.r.DeleteProfilesBalance(ctx, profileID)
	if err != nil {
		return fmt.Errorf("BalanceService -> DeleteProfilesBalance -> %w", err)
	}
	return nil
}
