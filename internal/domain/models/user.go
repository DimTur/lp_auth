package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	UserRoleDefault = "user"
	UserRoleAdmin   = "admin"
)

type User struct {
	ID       primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Email    string             `json:"email" bson:"email"`
	PassHash []byte             `json:"pass_hash" bson:"pass_hash"`
	Name     string             `json:"name" bson:"name"`
	Role     string             `json:"role" bson:"role"`
	Created  time.Time          `json:"created" bson:"created"`
	Updated  time.Time          `json:"updated" bson:"updated"`
}

type CreateUser struct {
	Email    string `json:"email" bson:"email" validate:"required"`
	Password string `json:"password" bson:"password" validate:"required"`
	Name     string `json:"name" bson:"name,omitempty"`
}

type DBCreateUser struct {
	ID       primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Email    string             `json:"email" bson:"email" validate:"required"`
	PassHash []byte             `json:"pass_hash" bson:"pass_hash" validate:"required"`
	Name     string             `json:"name" bson:"name,omitempty"`
	Role     string             `json:"role" bson:"role"`
	Created  time.Time          `json:"created" bson:"created,omitempty" validate:"required"`
	Updated  time.Time          `json:"updated" bson:"updated,omitempty" validate:"required"`
}

type UserRole struct {
	Role string `json:"role" bson:"role"`
}
