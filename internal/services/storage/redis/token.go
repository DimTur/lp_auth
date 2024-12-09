package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/DimTur/lp_auth/internal/services/storage"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func (r *RedisClient) SaveRefreshTokenToRedis(ctx context.Context, token *CreateRefreshToken) error {
	const op = "storage.redis.SaveRefreshToken"

	ttl := time.Until(token.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("%s: %w", op, storage.ErrTokenExpired)
	}

	hashFields := map[string]interface{}{
		"user_id":       token.UserID,
		"refresh_token": token.Token,
	}

	key := fmt.Sprintf("%s_%s", token.Token, token.UserID)
	err := r.client.HSet(ctx, key, hashFields).Err()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	err = r.client.Expire(ctx, token.Token, ttl).Err()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (r *RedisClient) FindRefreshToken(ctx context.Context, userID string) (*RefreshTokenFromRedis, error) {
	const op = "storage.redis.FindRefreshToken"

	pattern := fmt.Sprintf("*_%s", userID)
	tokens, err := r.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if len(tokens) == 0 {
		return nil, fmt.Errorf("%s: %w", op, storage.ErrNoTokensFound)
	}

	lastToken := tokens[len(tokens)-1]

	var token RefreshToken
	err = r.client.HGetAll(ctx, lastToken).Scan(&token)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &RefreshTokenFromRedis{
		UserID: token.UserID,
		Token:  token.Token,
	}, nil
}

func (r *RedisClient) GetUserIDByToken(ctx context.Context, token string) (primitive.ObjectID, error) {
	const op = "storage.redis.GetUserIDByToken"

	userIDStr, err := r.client.Get(ctx, token).Result()
	if err == redis.Nil {
		return primitive.ObjectID{}, fmt.Errorf("%s: %w", op, storage.ErrTokenNotFound)
	}
	if err != nil {
		return primitive.ObjectID{}, fmt.Errorf("%s: %w", op, err)
	}

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		return primitive.ObjectID{}, fmt.Errorf("%s: invalid user ID - %v", op, err)
	}

	return userID, nil
}

func (r *RedisClient) DeleteRefreshToken(ctx context.Context, token string) error {
	const op = "storage.redis.DeleteRefreshToken"

	_, err := r.client.Del(ctx, token).Result()
	if err == redis.Nil {
		return fmt.Errorf("%s: %w", op, storage.ErrTokenNotFound)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
