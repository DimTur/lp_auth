package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	UserRoleDefault    = "user"
	UserRoleAdmin      = "admin"
	UserRoleGroupAdmin = "group_admin"
)

type User struct {
	ID       string    `json:"id" bson:"_id,omitempty"`
	Email    string    `json:"email" bson:"email"`
	PassHash []byte    `json:"pass_hash" bson:"pass_hash"`
	Name     string    `json:"name" bson:"name"`
	Role     string    `json:"role" bson:"role"`
	TgLink   string    `json:"tg_link" bson:"tg_link"`
	Created  time.Time `json:"created" bson:"created"`
	Updated  time.Time `json:"updated" bson:"updated"`
}

type LogInUser struct {
	ID       string `json:"id" bson:"_id,omitempty"`
	Email    string `json:"email" bson:"email"`
	PassHash []byte `json:"pass_hash" bson:"pass_hash"`
}

type CreateUser struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
	Name     string `json:"name,omitempty"`
}

type UpdateUserInfo struct {
	ID     string `json:"id" validate:"required"`
	Email  string `json:"email,omitempty"`
	Name   string `json:"name,omitempty"`
	TgLink string `json:"tg_link,omitempty"`
}

type DBCreateUser struct {
	ID       primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Email    string             `json:"email" bson:"email" validate:"required,email"`
	PassHash []byte             `json:"pass_hash" bson:"pass_hash" validate:"required"`
	Name     string             `json:"name" bson:"name,omitempty"`
	Role     string             `json:"role" bson:"role"`
	Created  time.Time          `json:"created" bson:"created" validate:"required"`
	Updated  time.Time          `json:"updated" bson:"updated" validate:"required"`
}

type DBUpdateUserInfo struct {
	ID      string    `bson:"_id,omitempty" validate:"required"`
	Email   string    `bson:"email,omitempty"`
	Name    string    `bson:"name,omitempty"`
	TgLink  string    `bson:"tg_link,omitempty"`
	ChatID  string    `bson:"chat_id,omitempty"`
	Updated time.Time `bson:"updated,omitempty"`
}

type UserRole struct {
	Role string `json:"role" bson:"role"`
}

type UserChatID struct {
	ChatID string `json:"chat_id" bson:"chat_id"`
}
