package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/distuurbia/tradeAPI/internal/middleware/mocks"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestJWTMiddleware(t *testing.T) {
	s := new(mocks.ProfileService)

	claims := &jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
		"id":  uuid.New(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("roapjumping"))
	require.NoError(t, err)
	token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("roapjumping"), nil
	})
	require.NoError(t, err)
	testTokenString := "Bearer " + tokenString

	s.On("ExtractTokenFromAuthHeader", mock.AnythingOfType("string")).Return(tokenString, nil)
	s.On("ValidateToken", mock.AnythingOfType("string")).Return(token, nil)

	cm := NewCustomMiddleware(s)

	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", testTokenString)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	jwtMiddleware := cm.JWTMiddleware(func(c echo.Context) error {
		return c.String(http.StatusOK, "Authorized")
	})
	err = jwtMiddleware(c)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Code)
}
