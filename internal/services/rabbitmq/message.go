package rabbitmq

import "github.com/DimTur/lp_auth/internal/services/storage/redis"

type MsgOTP struct {
	Otp    redis.CreateOTP `json:"otp"`
	ChatID int             `json:"chat_id"`
}
