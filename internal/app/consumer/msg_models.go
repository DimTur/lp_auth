package consumer

import "time"

type SharePlanForUsers struct {
	ChannelID int64     `json:"channel_id" validate:"required"`
	PlanID    int64     `json:"plan_id" validate:"required"`
	UserIDs   []string  `json:"user_ids" validate:"required"`
	CreatedBy string    `json:"created_by" validate:"required"`
	CreatedAt time.Time `json:"created_at" validate:"required"`
}
