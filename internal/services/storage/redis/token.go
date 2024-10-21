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
		"user_id": token.UserID.Hex(),
	}

	err := r.client.HSet(ctx, token.Token, hashFields).Err()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	err = r.client.Expire(ctx, token.Token, ttl).Err()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (r *RedisClient) FindRefreshToken(ctx context.Context, userID primitive.ObjectID) (*RefreshToken, error) {
	const op = "storage.redis.FindRefreshToken"

	pattern := fmt.Sprintf("*_%s", userID.Hex())
	tokens, err := r.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if len(tokens) == 0 {
		return nil, fmt.Errorf("%s: no tokens found for user", op)
	}

	lastToken := tokens[len(tokens)-1]

	var token RefreshTokenToRedis
	err = r.client.HGetAll(ctx, lastToken).Scan(&token)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	userIDObj, err := primitive.ObjectIDFromHex(token.UserID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, storage.ErrUserIdConversion)
	}

	return &RefreshToken{
		UserID: userIDObj,
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

// func (r *RedisClient) FindRefreshToken(ctx context.Context, userID primitive.ObjectID) (*models.RefreshToken, error) {
// 	const op = "storage.mongodb.FindRefreshToken"

// 	coll := m.client.Database(m.dbname).Collection("tokens")

// 	filter := bson.M{"user_id": userID}

// 	var refToken models.RefreshToken
// 	err := coll.FindOne(ctx, filter).Decode(&refToken)
// 	if err != nil {
// 		if errors.Is(err, mongo.ErrNoDocuments) {
// 			return &refToken, fmt.Errorf("%s: %w", op, storage.ErrTokenNotFound)
// 		}

// 		return &refToken, fmt.Errorf("%s: %w", op, err)
// 	}

// 	return &refToken, nil
// }

// func (m *MClient) DeleteRefreshToken(ctx context.Context, token string) error {
// 	const op = "storage.mongodb.DeleteRefreshToken"

// 	coll := m.client.Database(m.dbname).Collection("tokens")

// 	filter := bson.M{"token": token}

// 	result, err := coll.DeleteOne(ctx, filter)
// 	if err != nil {
// 		return fmt.Errorf("%s: %w", op, err)
// 	}

// 	if result.DeletedCount == 0 {
// 		return fmt.Errorf("%s: token not found", op)
// 	}

// 	return nil
// }
