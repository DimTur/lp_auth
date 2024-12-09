package models

import (
	"time"
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
	IsAdmin  bool      `json:"is_admin" bson:"is_admin"`
	TgLink   string    `json:"tg_link" bson:"tg_link"`
	Created  time.Time `json:"created" bson:"created"`
	Updated  time.Time `json:"updated" bson:"updated"`
}

type DBUser struct {
	ID       string    `bson:"_id,omitempty"`
	Email    string    `bson:"email"`
	PassHash []byte    `bson:"pass_hash"`
	Name     string    `bson:"name"`
	IsAdmin  bool      `bson:"is_admin"`
	TgLink   string    `bson:"tg_link"`
	Created  time.Time `bson:"created"`
	Updated  time.Time `bson:"updated"`
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
	ID      string `json:"id" validate:"required"`
	Email   string `json:"email,omitempty"`
	Name    string `json:"name,omitempty"`
	TgLink  string `json:"tg_link,omitempty"`
	IsAdmin bool   `json:"is_admin,omitempty"`
}

type DBCreateUser struct {
	ID       string    `bson:"_id,omitempty"`
	Email    string    `bson:"email" validate:"required,email"`
	PassHash []byte    `bson:"pass_hash" validate:"required"`
	Name     string    `bson:"name,omitempty"`
	IsAdmin  bool      `bson:"is_admin"`
	Created  time.Time `bson:"created" validate:"required"`
	Updated  time.Time `bson:"updated" validate:"required"`
}

type DBUpdateUserInfo struct {
	ID      string    `bson:"_id,omitempty" validate:"required"`
	Email   string    `bson:"email,omitempty"`
	Name    string    `bson:"name,omitempty"`
	IsAdmin *bool     `bson:"is_admin"`
	TgLink  string    `bson:"tg_link,omitempty"`
	ChatID  string    `bson:"chat_id,omitempty"`
	Updated time.Time `bson:"updated,omitempty"`
}

type UserRoles struct {
	IsAdmin bool `json:"is_admin" bson:"is_admin"`
}

type UserChatID struct {
	ChatID string `json:"chat_id" bson:"chat_id"`
}

type UserNotification struct {
	UserID string `bson:"_id"`
	Email  string `bson:"email"`
	TgLink string `bson:"tg_link"`
	ChatID string `bson:"chat_id"`
}
