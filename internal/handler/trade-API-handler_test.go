package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/distuurbia/tradeAPI/internal/handler/mocks"
	"github.com/distuurbia/tradeAPI/internal/model"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestSignUp(t *testing.T) {
	profileSrvc := new(mocks.ProfileService)
	h := NewTradeAPIHandler(profileSrvc, nil, validate)

	jsonData, err := json.Marshal(testSignUpRequest)
	require.NoError(t, err)

	profileSrvc.On("SignUp", mock.Anything, mock.AnythingOfType("*model.Profile")).Return(nil).Once()
	e := echo.New()

	req := httptest.NewRequest(http.MethodPost, "/signUp", bytes.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = h.SignUp(c)
	require.NoError(t, err)
}

func TestLogin(t *testing.T) {
	profileSrvc := new(mocks.ProfileService)
	h := NewTradeAPIHandler(profileSrvc, nil, validate)

	jsonData, err := json.Marshal(testLoginRequest)
	require.NoError(t, err)

	var tokenPair = model.TokenPair{
		AccessToken:  "accessToken",
		RefreshToken: "refreshToken",
	}

	profileSrvc.On("Login", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8")).Return(&tokenPair, nil).Once()
	e := echo.New()

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = h.Login(c)
	require.NoError(t, err)

	response := rec.Result()

	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	defer response.Body.Close()

	require.True(t, strings.Contains(string(body), "accessToken") && strings.Contains(string(body), "refreshToken"))
}

func TestRefresh(t *testing.T) {
	profileSrvc := new(mocks.ProfileService)
	h := NewTradeAPIHandler(profileSrvc, nil, validate)

	jsonData, err := json.Marshal(testTokenPair)
	require.NoError(t, err)

	var tokenPair = model.TokenPair{
		AccessToken:  "accessToken",
		RefreshToken: "refreshToken",
	}

	profileSrvc.On("Refresh", mock.Anything, mock.AnythingOfType("*model.TokenPair")).Return(&tokenPair, nil).Once()
	e := echo.New()

	req := httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = h.Refresh(c)
	require.NoError(t, err)

	response := rec.Result()

	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	defer response.Body.Close()

	require.True(t, strings.Contains(string(body), "accessToken") && strings.Contains(string(body), "refreshToken"))
}

func TestDeleteProfile(t *testing.T) {
	profileSrvc := new(mocks.ProfileService)
	balanceSrvc := new(mocks.BalanceService)
	h := NewTradeAPIHandler(profileSrvc, balanceSrvc, validate)

	testID := uuid.New()

	profileSrvc.On("ExtractIDFromAuthHeader", mock.Anything, mock.AnythingOfType("string")).Return(testID, nil).Once()
	profileSrvc.On("DeleteProfile", mock.Anything, mock.AnythingOfType("uuid.UUID")).Return(nil).Once()
	balanceSrvc.On("DeleteProfilesBalance", mock.Anything, mock.AnythingOfType("uuid.UUID")).Return(nil).Once()
	e := echo.New()

	req := httptest.NewRequest(http.MethodPost, "/deleteProfile", http.NoBody)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)
	c.Request().Header.Set("Authorization", "someAuth")

	err := h.DeleteProfile(c)
	require.NoError(t, err)

	response := rec.Result()

	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	defer response.Body.Close()

	require.True(t, strings.Contains(string(body), testID.String()))
}

func TestAddBalanceChangeDeposit(t *testing.T) {
	profileSrvc := new(mocks.ProfileService)
	balanceSrvc := new(mocks.BalanceService)
	h := NewTradeAPIHandler(profileSrvc, balanceSrvc, validate)

	testAmount := struct {
		Amount float64
	}{}
	testAmount.Amount = 505.542
	jsonData, err := json.Marshal(testAmount)
	require.NoError(t, err)

	testID := uuid.New()

	profileSrvc.On("ExtractIDFromAuthHeader", mock.Anything, mock.AnythingOfType("string")).Return(testID, nil).Once()
	balanceSrvc.On("AddBalanceChange", mock.Anything, mock.AnythingOfType("uuid.UUID"), mock.AnythingOfType("float64")).Return(nil).Once()
	e := echo.New()

	req := httptest.NewRequest(http.MethodPost, "/deposit", bytes.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)
	c.Request().Header.Set("Authorization", "someAuth")

	err = h.AddBalanceChange(c)
	require.NoError(t, err)

	response := rec.Result()

	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	defer response.Body.Close()

	require.True(t, strings.Contains(string(body), testID.String()) && strings.Contains(string(body), fmt.Sprintf("%v", testAmount.Amount)))
}

func TestAddBalanceChangeWithdraw(t *testing.T) {
	profileSrvc := new(mocks.ProfileService)
	balanceSrvc := new(mocks.BalanceService)
	h := NewTradeAPIHandler(profileSrvc, balanceSrvc, validate)

	testAmount := struct {
		Amount float64
	}{}
	testAmount.Amount = 505.542
	jsonData, err := json.Marshal(testAmount)
	require.NoError(t, err)

	testID := uuid.New()
	testBalance := float64(1000)

	profileSrvc.On("ExtractIDFromAuthHeader", mock.Anything, mock.AnythingOfType("string")).Return(testID, nil).Once()
	balanceSrvc.On("AddBalanceChange", mock.Anything, mock.AnythingOfType("uuid.UUID"), mock.AnythingOfType("float64")).Return(nil).Once()
	balanceSrvc.On("GetBalance", mock.Anything, mock.AnythingOfType("uuid.UUID")).Return(testBalance, nil)
	e := echo.New()

	req := httptest.NewRequest(http.MethodPost, "/withdraw", bytes.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)
	c.Request().Header.Set("Authorization", "someAuth")

	err = h.AddBalanceChange(c)
	require.NoError(t, err)

	response := rec.Result()

	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	defer response.Body.Close()

	require.True(t, strings.Contains(string(body), testID.String()) && strings.Contains(string(body), fmt.Sprintf("%v", testAmount.Amount)))
}

func TestGetBalance(t *testing.T) {
	profileSrvc := new(mocks.ProfileService)
	balanceSrvc := new(mocks.BalanceService)
	h := NewTradeAPIHandler(profileSrvc, balanceSrvc, validate)

	testBalance := float64(1000)

	testID := uuid.New()

	profileSrvc.On("ExtractIDFromAuthHeader", mock.Anything, mock.AnythingOfType("string")).Return(testID, nil).Once()
	balanceSrvc.On("GetBalance", mock.Anything, mock.AnythingOfType("uuid.UUID")).Return(testBalance, nil)
	e := echo.New()

	req := httptest.NewRequest(http.MethodPost, "/getBalance", http.NoBody)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)
	c.Request().Header.Set("Authorization", "someAuth")

	err := h.GetBalance(c)
	require.NoError(t, err)

	response := rec.Result()

	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	defer response.Body.Close()

	require.True(t, strings.Contains(string(body), testID.String()) && strings.Contains(string(body), fmt.Sprintf("%v", testBalance)))
}
