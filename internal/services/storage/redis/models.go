package redis

import (
	"time"
)

type CreateRefreshToken struct {
	UserID    string    `json:"user_id" redis:"user_id" validate:"required"`
	Token     string    `json:"token" redis:"token" validate:"required"`
	ExpiresAt time.Time `json:"expires_at" redis:"expires_at" validate:"required"`
}

type RefreshTokenToRedis struct {
	UserID string `redis:"user_id"`
	Token  string `redis:"refresh_token"`
}

type RefreshToken struct {
	UserID string `json:"user_id" redis:"user_id"`
	Token  string `json:"token" redis:"refresh_token"`
}

type RefreshTokenFromRedis struct {
	UserID string `json:"user_id"`
	Token  string `json:"token"`
}

type CreateOTP struct {
	UserID    string    `json:"user_id" redis:"user_id" validate:"required"`
	Code      string    `json:"code" redis:"code" validate:"required"`
	ExpiresAt time.Time `json:"expires_at" redis:"expires_at" validate:"required"`
	Used      bool      `json:"used" redis:"used" validate:"required"`
}

type UserOTP struct {
	UserID string `json:"user_id" redis:"user_id"`
	Code   string `json:"code" redis:"code"`
	Used   bool   `json:"used" redis:"used"`
}

type UserOTPFromRedis struct {
	UserID string `json:"user_id" redis:"user_id"`
	Code   string `json:"code" redis:"code"`
	Used   bool   `json:"used" redis:"used"`
}
