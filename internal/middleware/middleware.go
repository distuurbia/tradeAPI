// Package middleware need fop an authorization in our requests
package middleware

import (
	"net/http"
	"time"

	"github.com/distuurbia/tradeAPI/internal/service"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

type CustomMiddleware struct {
	s service.ProfileService
}

func NewCustomMiddleware(s service.ProfileService) *CustomMiddleware {
	return &CustomMiddleware{s: s}
}

// JWTMiddleware makes an authorization through access token
func (cm *CustomMiddleware) JWTMiddleware(next echo.HandlerFunc) echo.HandlerFunc{
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			logrus.Errorf("CustomMiddleware -> JWTMiddleware -> error: empty auth header")
			return echo.NewHTTPError(http.StatusUnauthorized, "empty authorization header")
		}

		tokenString , err := cm.s.ExtractTokenFromAuthHeader(authHeader)
		if tokenString == "" {
			logrus.Errorf("CustomMiddleware -> JWTMiddleware -> error: empty token string")
			return echo.NewHTTPError(http.StatusUnauthorized, "empty access token")
		}

		token, err := cm.s.ValidateToken(tokenString)
		if err != nil{
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
