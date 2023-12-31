// Package handler contains all work with handling the requests
package handler

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strings"

	"github.com/distuurbia/tradeAPI/internal/model"
	"github.com/go-playground/validator"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

// ProfileService is an interface of service.ProfileService
type ProfileService interface {
	SignUp(ctx context.Context, profile *model.Profile) error
	Login(ctx context.Context, username string, password []byte) (*model.TokenPair, error)
	Refresh(ctx context.Context, tokenPair *model.TokenPair) (*model.TokenPair, error)
	DeleteProfile(ctx context.Context, id uuid.UUID) error
	ExtractIDFromAuthHeader(authHeaderString string) (uuid.UUID, error)
}

// BalanceService is an interface of service.BalanceService
type BalanceService interface {
	AddBalanceChange(ctx context.Context, profileID uuid.UUID, amount float64) error
	GetBalance(ctx context.Context, profileID uuid.UUID) (float64, error)
	DeleteProfilesBalance(ctx context.Context, profileID uuid.UUID) error
}

// TradeAPIHandler contains profile and balance services, also validator
type TradeAPIHandler struct {
	profileSrvc ProfileService
	balanceSrvc BalanceService
	validate    *validator.Validate
}

// NewTradeAPIHandler creates an object of *TradeAPIHandler filled with provided fields
func NewTradeAPIHandler(profileSrvc ProfileService, balanceSrvc BalanceService, validate *validator.Validate) *TradeAPIHandler {
	return &TradeAPIHandler{profileSrvc: profileSrvc, balanceSrvc: balanceSrvc, validate: validate}
}

// SignUp validates fields of signUpRequest and calls method SignUp of ProfileService
func (h *TradeAPIHandler) SignUp(c echo.Context) error {
	var signUpRequest model.SignUpRequest
	err := c.Bind(&signUpRequest)
	if err != nil {
		logrus.Errorf("TradeAPIHandler -> SignUp -> %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, "failed to bind info")
	}

	err = h.validate.StructCtx(c.Request().Context(), signUpRequest)
	if err != nil {
		logrus.WithField("signUpRequest", signUpRequest).Errorf("TradeAPIHandler -> SignUp -> %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, "failed to validate profile")
	}

	var profile = model.Profile{
		ID:       uuid.New(),
		Username: signUpRequest.Username,
		Password: []byte(signUpRequest.Password),
		Country:  signUpRequest.Country,
		Age:      signUpRequest.Age,
	}

	err = h.profileSrvc.SignUp(c.Request().Context(), &profile)
	if err != nil {
		logrus.WithField("profile", profile).Errorf("TradeAPIHandler -> SignUp -> %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, "failed to signup profile")
	}
	output := fmt.Sprintf("created a profile with ID: %v", profile.ID.String())

	return c.JSON(http.StatusCreated, output)
}

// Login validates fields of loginRequest and cals the method Login of ProfileService
func (h *TradeAPIHandler) Login(c echo.Context) error {
	var loginRequest model.LoginRequest

	err := c.Bind(&loginRequest)
	if err != nil {
		logrus.Errorf("TradeAPIHandler -> Login -> %v", err)
		return echo.NewHTTPError(http.StatusUnauthorized, "failed to bind info")
	}

	err = h.validate.StructCtx(c.Request().Context(), loginRequest)
	if err != nil {
		logrus.WithField("loginRequest", loginRequest).Errorf("TradeAPIHandler -> Login -> %v", err)
		return echo.NewHTTPError(http.StatusUnauthorized, "failed to validate login or password")
	}

	tokenPair, err := h.profileSrvc.Login(c.Request().Context(), loginRequest.Username, []byte(loginRequest.Password))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"loginRequest.Username": loginRequest.Username,
			"loginRequest.Password": loginRequest.Password,
		}).Errorf("TradeAPIHandler -> Login -> %v", err)
		return echo.NewHTTPError(http.StatusUnauthorized, "failed to login")
	}

	return c.JSON(http.StatusOK, echo.Map{
		"Access token":  tokenPair.AccessToken,
		"Refresh token": tokenPair.RefreshToken,
	})
}

// Refresh validates fields and calls the Refresh method of ProfileService
func (h *TradeAPIHandler) Refresh(c echo.Context) error {
	var tokenPair model.TokenPair
	err := c.Bind(&tokenPair)
	if err != nil {
		logrus.Errorf("TradeAPIHandler -> Refresh -> %v", err)
		return echo.NewHTTPError(http.StatusUnauthorized, "failed to bind info")
	}

	err = h.validate.StructCtx(c.Request().Context(), tokenPair)
	if err != nil {
		logrus.WithField("tokenPair", tokenPair).Errorf("TradeAPIHandler -> Refresh -> %v", err)
		return echo.NewHTTPError(http.StatusUnauthorized, "failed to validate access or refresh token")
	}

	newTokenPair, err := h.profileSrvc.Refresh(c.Request().Context(), &tokenPair)
	if err != nil {
		logrus.WithField("tokenPair", tokenPair).Errorf("TradeAPIHandler -> Refresh -> %v", err)
		return echo.NewHTTPError(http.StatusUnauthorized, "failed to generate new tokenPair")
	}

	return c.JSON(http.StatusOK, echo.Map{
		"Access token":  newTokenPair.AccessToken,
		"Refresh token": newTokenPair.RefreshToken,
	})
}

// DeleteProfile extcracts profileID from auth header and calls method DeleteProfile of ProfileService and DeleteProfilesBalance of BalanceService
func (h *TradeAPIHandler) DeleteProfile(c echo.Context) error {
	authHeaderString := c.Request().Header.Get("Authorization")
	profileID, err := h.profileSrvc.ExtractIDFromAuthHeader(authHeaderString)
	if err != nil {
		logrus.WithField("authHeaderString", authHeaderString).Errorf("TradeAPIHandler -> DeleteProfile -> %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, "failed exctract ID from accessToken")
	}

	err = h.profileSrvc.DeleteProfile(c.Request().Context(), profileID)
	if err != nil {
		logrus.WithField("profileID", profileID).Errorf("TradeAPIHandler -> DeleteProfile -> %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, "failed to delete profile with provided id")
	}
	err = h.balanceSrvc.DeleteProfilesBalance(c.Request().Context(), profileID)
	if err != nil {
		logrus.WithField("profileID", profileID).Errorf("TradeAPIHandler -> DeleteProfile -> %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, "failed to delete balances with provided id")
	}
	output := fmt.Sprintf("deleted profile and its balance with ID: %v", profileID.String())

	return c.JSON(http.StatusOK, output)
}

// AddBalanceChange extcracts profileID from auth header and calls AddBalanceChange method of BalanceService
func (h *TradeAPIHandler) AddBalanceChange(c echo.Context) error {
	authHeaderString := c.Request().Header.Get("Authorization")
	profileID, err := h.profileSrvc.ExtractIDFromAuthHeader(authHeaderString)
	if err != nil {
		logrus.WithField("authHeaderString", authHeaderString).Errorf("TradeAPIHandler -> AddBalanceChange -> %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, "failed exctract ID from accessToken")
	}

	bindAmount := struct {
		Amount float64 `json:"amount" validate:"required,gt=0" form:"amount"`
	}{}

	err = c.Bind(&bindAmount)
	if err != nil {
		logrus.Errorf("TradeAPIHandler -> AddBalanceChange -> %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, "failed to bind amount")
	}

	err = h.validate.StructCtx(c.Request().Context(), bindAmount)
	if err != nil {
		logrus.WithField("bindAmount", bindAmount).Errorf("TradeAPIHandler -> AddBalanceChange -> %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, "failed to validate amount")
	}

	action := "deposited for"
	if strings.Contains(c.Request().RequestURI, "withdraw") {
		totalBalance, errGetBalance := h.balanceSrvc.GetBalance(c.Request().Context(), profileID)
		if errGetBalance != nil {
			logrus.WithField("profileID", profileID).Errorf("TradeAPIHandler -> AddBalanceChange -> %v", errGetBalance)
			return echo.NewHTTPError(http.StatusBadRequest, "failed to check balance of profile with ID: "+profileID.String())
		}
		if totalBalance < bindAmount.Amount {
			logrus.WithField("profileID", profileID).Errorf("TradeAPIHandler -> AddBalanceChange -> %v", errGetBalance)
			return echo.NewHTTPError(http.StatusBadRequest, "don't have enough balance on profile with ID: "+profileID.String())
		}
		bindAmount.Amount *= -1
		action = "withdrawed from"
	}

	err = h.balanceSrvc.AddBalanceChange(c.Request().Context(), profileID, bindAmount.Amount)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"profileID":         profileID,
			"bindAmount.Amount": bindAmount.Amount,
		}).Errorf("TradeAPIHandler -> AddBalanceChange -> %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, "failed to be "+action+" profile with ID: "+profileID.String())
	}
	output := fmt.Sprintf("Successfully %v %v profile with ID: %v", action, math.Abs(bindAmount.Amount), profileID)

	return c.JSON(http.StatusOK, output)
}

// GetBalance extcracts profileID from auth header and calls method GetBalance of BalanceService
func (h *TradeAPIHandler) GetBalance(c echo.Context) error {
	authHeaderString := c.Request().Header.Get("Authorization")
	profileID, err := h.profileSrvc.ExtractIDFromAuthHeader(authHeaderString)
	if err != nil {
		logrus.WithField("authHeaderString", authHeaderString).Errorf("TradeAPIHandler -> AddBalanceChange -> %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, "failed exctract ID from accessToken")
	}

	totalBalance, err := h.balanceSrvc.GetBalance(c.Request().Context(), profileID)
	if err != nil {
		logrus.WithField("profileID", profileID).Errorf("TradeAPIHandler -> DeleteProfile -> %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, "failed to parse id")
	}
	output := fmt.Sprintf("Total balance: %v of profile with ID: %v", totalBalance, profileID)
	return c.JSON(http.StatusOK, output)
}
