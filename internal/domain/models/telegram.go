package models

type SingInViaTg struct {
	Email string `json:"email" validate:"required"`
}

type LoginUserOTP struct {
	Email string `json:"email" validate:"required"`
	Code  string `json:"code" validate:"required"`
}
