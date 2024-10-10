package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type RefreshToken struct {
	Token  string             `json:"token" bson:"token"`
	UserID primitive.ObjectID `json:"user_id" bson:"user_id"`
}

type CreateRefreshToken struct {
	UserID    primitive.ObjectID `json:"user_id" bson:"user_id" validate:"required"`
	Token     string             `json:"token" bson:"token" validate:"required"`
	ExpiresAt time.Time          `json:"expires_at" bson:"expires_at" validate:"required"`
}

type LogInTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type AuthCheck struct {
	IsValid bool   `json:"is_valid"`
	UserId  string `json:"user_id"`
}
