package service

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/distuurbia/tradeAPI/internal/service/mocks"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestHashBytes(t *testing.T) {
	r := new(mocks.ProfileClientRepository)
	s := NewProfileService(r, &cfg)

	testBytes := []byte("test")
	hashedBytes, err := s.HashBytes(testBytes)
	require.NoError(t, err)

	err = bcrypt.CompareHashAndPassword(hashedBytes, testBytes)
	require.NoError(t, err)
}

func TestCompareHashAndBytes(t *testing.T) {
	r := new(mocks.ProfileClientRepository)
	s := NewProfileService(r, &cfg)

	testBytes := []byte("test")
	hashedBytes, err := s.HashBytes(testBytes)
	require.NoError(t, err)

	isEqual, err := s.CompareHashAndBytes(hashedBytes, testBytes)
	require.NoError(t, err)
	require.True(t, isEqual)

	testBytesTemp := []byte("test1")
	hashedBytes, err = s.HashBytes(testBytesTemp)
	require.NoError(t, err)

	isEqual, err = s.CompareHashAndBytes(hashedBytes, testBytes)
	require.Error(t, err)
	require.False(t, isEqual)
}

func TestValidateToken(t *testing.T) {
	r := new(mocks.ProfileClientRepository)
	s := NewProfileService(r, &cfg)
	testID := uuid.New()
	claims := &jwt.MapClaims{
		"exp": time.Now().Add(accessTokenExpiration).Unix(),
		"id":  testID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.cfg.SecretKey))
	require.NoError(t, err)

	testToken, err := s.ValidateToken(tokenString)
	require.NoError(t, err)

	require.True(t, testToken.Valid)
}

func TestGenerateJWT(t *testing.T) {
	r := new(mocks.ProfileClientRepository)
	s := NewProfileService(r, &cfg)

	testID := uuid.New()
	testTokenString, err := s.GenerateJWTToken(accessTokenExpiration, testID)
	require.NoError(t, err)

	testToken, err := s.ValidateToken(testTokenString)
	require.NoError(t, err)

	require.True(t, testToken.Valid)

	claims := testToken.Claims.(jwt.MapClaims)
	require.Equal(t, testID.String(), claims["id"])
}

func TestExtractIDFromAuthHeader(t *testing.T) {
	r := new(mocks.ProfileClientRepository)
	s := NewProfileService(r, &cfg)

	testID := uuid.New()
	testTokenString, err := s.GenerateJWTToken(accessTokenExpiration, testID)
	require.NoError(t, err)
	
	extractedID, err := s.ExtractIDFromAuthHeader("Bearer " + testTokenString)
	require.NoError(t, err)
	require.Equal(t, testID, extractedID)
}

func TestGenerateTokenPair(t *testing.T) {
	r := new(mocks.ProfileClientRepository)
	s := NewProfileService(r, &cfg)

	testID := uuid.New()
	testTokenPair, err := s.GenerateTokenPair(testID)
	require.NoError(t, err)

	accessToken, err := s.ValidateToken(testTokenPair.AccessToken)
	require.NoError(t, err)
	require.True(t, accessToken.Valid)

	refreshToken, err := s.ValidateToken(testTokenPair.RefreshToken)
	require.NoError(t, err)
	require.True(t, refreshToken.Valid)

	claimsAccess := accessToken.Claims.(jwt.MapClaims)
	require.Equal(t, testID.String(), claimsAccess["id"])

	claimsRefresh := refreshToken.Claims.(jwt.MapClaims)
	require.Equal(t, testID.String(), claimsRefresh["id"])
}

func TestSignUp(t *testing.T) {
	r := new(mocks.ProfileClientRepository)
	r.On("CreateProfile", mock.Anything, mock.AnythingOfType("*model.Profile")).Return(nil)

	s := NewProfileService(r, &cfg)

	err := s.SignUp(context.Background(), &testProfile)
	require.NoError(t, err)
}

func TestLogin(t *testing.T) {
	r := new(mocks.ProfileClientRepository)

	hashedbytes, err := bcrypt.GenerateFromPassword(testProfile.Password, bcryptCost)
	require.NoError(t, err)

	r.On("GetPasswordAndIDByUsername", mock.Anything, mock.AnythingOfType("string")).
		Return(testProfile.ID, hashedbytes, nil)
	r.On("AddRefreshToken", mock.Anything, mock.AnythingOfType("[]uint8"), mock.AnythingOfType("uuid.UUID")).
		Return(nil)

	s := NewProfileService(r, &cfg)

	testTokenPair, err := s.Login(context.Background(), testProfile.Username, testProfile.Password)
	require.NoError(t, err)

	accessToken, err := s.ValidateToken(testTokenPair.AccessToken)
	require.NoError(t, err)
	require.True(t, accessToken.Valid)

	refreshToken, err := s.ValidateToken(testTokenPair.RefreshToken)
	require.NoError(t, err)
	require.True(t, refreshToken.Valid)

	claimsAccess := accessToken.Claims.(jwt.MapClaims)
	require.Equal(t, testProfile.ID.String(), claimsAccess["id"])

	claimsRefresh := refreshToken.Claims.(jwt.MapClaims)
	require.Equal(t, testProfile.ID.String(), claimsRefresh["id"])
}

func TestTokensIDCompare(t *testing.T) {
	r := new(mocks.ProfileClientRepository)
	s := NewProfileService(r, &cfg)

	tokenPair, err := s.GenerateTokenPair(testProfile.ID)
	require.NoError(t, err)

	id, err := s.TokensIDCompare(tokenPair)
	require.NoError(t, err)
	require.Equal(t, testProfile.ID, id)
}

func TestRefresh(t *testing.T) {
	r := new(mocks.ProfileClientRepository)
	s := NewProfileService(r, &cfg)

	tokenPair, err := s.GenerateTokenPair(testProfile.ID)
	require.NoError(t, err)
	sum := sha256.Sum256([]byte(tokenPair.RefreshToken))

	hashedbytes, err := bcrypt.GenerateFromPassword(sum[:], bcryptCost)
	require.NoError(t, err)

	r.On("GetRefreshTokenByID", mock.Anything, mock.AnythingOfType("uuid.UUID")).
		Return(hashedbytes, nil)
	r.On("AddRefreshToken", mock.Anything, mock.AnythingOfType("[]uint8"), mock.AnythingOfType("uuid.UUID")).
		Return(nil)

	testTokenPair, err := s.Refresh(context.Background(), tokenPair)
	require.NoError(t, err)

	accessToken, err := s.ValidateToken(testTokenPair.AccessToken)
	require.NoError(t, err)
	require.True(t, accessToken.Valid)

	refreshToken, err := s.ValidateToken(testTokenPair.RefreshToken)
	require.NoError(t, err)
	require.True(t, refreshToken.Valid)

	claimsAccess := accessToken.Claims.(jwt.MapClaims)
	require.Equal(t, testProfile.ID.String(), claimsAccess["id"])

	claimsRefresh := refreshToken.Claims.(jwt.MapClaims)
	require.Equal(t, testProfile.ID.String(), claimsRefresh["id"])
}

func TestDeleteProfile(t *testing.T) {
	r := new(mocks.ProfileClientRepository)

	r.On("DeleteProfile", mock.Anything, mock.AnythingOfType("uuid.UUID")).Return(nil)

	s := NewProfileService(r, &cfg)

	err := s.DeleteProfile(context.Background(), uuid.New())
	require.NoError(t, err)
}