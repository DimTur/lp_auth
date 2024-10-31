package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/DimTur/lp_auth/internal/services/storage"
	"github.com/redis/go-redis/v9"
)

func (r *RedisClient) SaveOTPToRedis(ctx context.Context, otp *CreateOTP) error {
	const op = "storage.redis.SaveOTPToRedis"

	ttl := time.Until(otp.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("%s: %w", op, storage.ErrOTPExpired)
	}

	hashFields := map[string]interface{}{
		"user_id": otp.UserID,
		"used":    otp.Used,
	}

	err := r.client.HSet(ctx, otp.Code, hashFields).Err()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	err = r.client.Expire(ctx, otp.Code, ttl).Err()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (r *RedisClient) FindOTPCode(ctx context.Context, code string) (*UserOTPFromRedis, error) {
	const op = "storage.redis.FindOTPCode"

	var otp UserOTP
	err := r.client.HGetAll(ctx, code).Scan(&otp)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &UserOTPFromRedis{
		UserID: otp.UserID,
		Code:   otp.Code,
		Used:   otp.Used,
	}, nil
}

func (r *RedisClient) DeleteUserOTP(ctx context.Context, code string) error {
	const op = "storage.redis.DeleteUserOTP"

	_, err := r.client.Del(ctx, code).Result()
	if err == redis.Nil {
		return fmt.Errorf("%s: %w", op, storage.ErrOTPNotFound)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
