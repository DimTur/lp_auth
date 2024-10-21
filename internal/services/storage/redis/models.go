package redis

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type CreateRefreshToken struct {
	UserID    primitive.ObjectID `json:"user_id" redis:"user_id" validate:"required"`
	Token     string             `json:"token" redis:"redis" validate:"required"`
	ExpiresAt time.Time          `json:"expires_at" redis:"expires_at" validate:"required"`
}

type RefreshTokenToRedis struct {
	Token  string `json:"token" redis:"token"`
	UserID string `json:"user_id" redis:"user_id"`
}

type RefreshToken struct {
	Token  string             `json:"token" redis:"token"`
	UserID primitive.ObjectID `json:"user_id" redis:"user_id"`
}
