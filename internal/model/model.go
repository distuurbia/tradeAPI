// Package model contains models of project
package model

import "github.com/google/uuid"

// Profile contains fields that we have in our postgresql table profiles
type Profile struct {
	Age          int32 `validate:"gte=18,lte=120"`
	ID           uuid.UUID
	Username     string `validate:"required,min=4,max=20"`
	Country      string `validate:"required,min=2"`
	Password     []byte `validate:"required,min=4"`
	RefreshToken []byte
}

// SignUpRequest contains fields that we have in our postgresql table profiles
type SignUpRequest struct {
	Age      int32  `json:"age" validate:"gte=18,lte=120" form:"age"`
	Username string `json:"username" validate:"required,min=4,max=20" form:"username"`
	Country  string `json:"country" validate:"required,min=2" form:"country"`
	Password string `json:"password" validate:"required,min=4" form:"password"`
}

// LoginRequest contains fields that we use for bind the username and password
type LoginRequest struct {
	Username string `json:"username" validate:"required,min=4,max=20" form:"username"`
	Password string `json:"password" validate:"required,min=4,max=20" form:"password"`
}

// TokenPair contains an access and a refresh tokens
type TokenPair struct {
	AccessToken  string `json:"accessToken" validate:"required" form:"accessToken"`
	RefreshToken string `json:"refreshToken" validate:"required" form:"refreshToken"`
}
