// Package middleware contains an authorization by jwt token when requests are sent
package middleware

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

// ProfileService is an interface of service.ProfileService
type ProfileService interface {
	ExtractTokenFromAuthHeader(authHeaderString string) (string, error)
	ValidateToken(tokenString string) (*jwt.Token, error)
}

// CustomMiddleware is a structure that contains ProfileService interface and need for authentificzation by jwt token
type CustomMiddleware struct {
	s ProfileService
}

// NewCustomMiddleware is a constructor for CustomMiddleware structure
func NewCustomMiddleware(s ProfileService) *CustomMiddleware {
	return &CustomMiddleware{s: s}
}

// JWTMiddleware makes an authorization through access token
func (cm *CustomMiddleware) JWTMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			logrus.Errorf("CustomMiddleware -> JWTMiddleware -> error: empty auth header")
			return echo.NewHTTPError(http.StatusUnauthorized, "empty authorization header")
		}

		tokenString, err := cm.s.ExtractTokenFromAuthHeader(authHeader)
		if err != nil {
			logrus.Errorf("CustomMiddleware -> JWTMiddleware -> %v", err)
			return echo.NewHTTPError(http.StatusUnauthorized, "failed to extract token from auth header")
		}

		token, err := cm.s.ValidateToken(tokenString)
		if err != nil {
			logrus.Errorf("CustomMiddleware -> JWTMiddleware -> %v", err)
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
		}
		if !token.Valid {
			logrus.Errorf("CustomMiddleware -> JWTMiddleware -> error: invalid token")
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			exp := claims["exp"].(float64)
			if exp < float64(time.Now().Unix()) {
				logrus.Errorf("CustomMiddleware -> JWTMiddleware -> error: token is expired")
				return echo.NewHTTPError(http.StatusUnauthorized, "token is expired")
			}
		}
		return next(c)
	}
}
