package models

type LogInViaTg struct {
	Email string `json:"email" validate:"required"`
}

type LoginUserOTP struct {
	Email string `json:"email" validate:"required"`
	Code  string `json:"code" validate:"required"`
}

type UserTg struct {
	TgLink string `json:"tg_link"`
	ChatID string `json:"chat_id"`
}
