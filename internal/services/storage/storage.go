package storage

import (
	"errors"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

var (
	ErrUserExitsts      = errors.New("user already exists")
	ErrUserNotFound     = errors.New("user not found")
	ErrUserIdConversion = errors.New("user conversion failed")
	ErrAppNotFound      = errors.New("app not found")
	ErrAppExists        = errors.New("app already exists")
	ErrTokenExists      = errors.New("refresh token already exists")
	ErrTokenNotFound    = errors.New("refresh token not found")
	ErrTokenExpired     = errors.New("token is already expired")

	NilID = primitive.NilObjectID
)
