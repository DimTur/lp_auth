package storage

import (
	"errors"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

var (
	ErrUserExitsts      = errors.New("user already exists")
	ErrUserNotFound     = errors.New("user not found")
	ErrUserIdConversion = errors.New("user conversion failed")

	ErrAppNotFound = errors.New("app not found")
	ErrAppExists   = errors.New("app already exists")

	ErrTokenExists   = errors.New("refresh token already exists")
	ErrTokenNotFound = errors.New("refresh token not found")
	ErrTokenExpired  = errors.New("token is already expired")

	ErrOTPNotFound = errors.New("otp not found")
	ErrOTPExpired  = errors.New("otp is already expired")

	ErrInvalidCredentials = errors.New("invalid credentials")

	ErrNoTokensFound = errors.New("no tokens found for user")

	ErrLgNotFound = errors.New("learning group not found")
	ErrLgExitsts  = errors.New("learning group already exists")

	ErrObjectID = errors.New("invalid ObjectID format")

	NilID = primitive.NilObjectID
)
