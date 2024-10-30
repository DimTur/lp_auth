package mongodb

import (
	"context"
	"errors"
	"fmt"

	"github.com/DimTur/lp_auth/internal/domain/models"
	"github.com/DimTur/lp_auth/internal/services/storage"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

const (
	CollAuth   = "users"
	CollTokens = "tokens"
)

func (m *MClient) SaveUser(ctx context.Context, user *models.DBCreateUser) error {
	const op = "storage.mongodb.SaveUser"

	coll := m.client.Database(m.dbname).Collection(CollAuth)
	_, err := coll.InsertOne(ctx, user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("%s: %w", op, storage.ErrUserExitsts)
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (m *MClient) FindUserByEmail(ctx context.Context, email string) (*models.User, error) {
	const op = "storage.mongodb.FindUserByEmail"

	coll := m.client.Database(m.dbname).Collection(CollAuth)

	filter := bson.M{"email": email}

	var user models.User
	err := coll.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		fmt.Printf("Decode error: %v\n", err)
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &user, nil
}

func (m *MClient) FindUserByTgLink(ctx context.Context, tgLink string) (*models.User, error) {
	const op = "storage.mongodb.FindUserByEmail"

	coll := m.client.Database(m.dbname).Collection(CollAuth)

	filter := bson.M{"tg_link": tgLink}

	var user models.User
	err := coll.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		fmt.Printf("Decode error: %v\n", err)
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &user, nil
}

func (m *MClient) UpdateUserInfo(ctx context.Context, userInfo *models.DBUpdateUserInfo) error {
	const op = "storage.mongodb.UpdateUserInfo"

	coll := m.client.Database(m.dbname).Collection(CollAuth)
	_, err := coll.UpdateByID(ctx, userInfo.ID, bson.M{
		"$set": userInfo,
	})
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("%s: %w", op, storage.ErrInvalidCredentials)
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (m *MClient) GetUserRole(ctx context.Context, userID primitive.ObjectID) (string, error) {
	const op = "storage.mongodb.GetUserRole"

	coll := m.client.Database(m.dbname).Collection(CollAuth)

	filter := bson.M{"_id": userID}

	var userRole models.UserRole
	err := coll.FindOne(ctx, filter).Decode(&userRole)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return userRole.Role, nil
}

func (m *MClient) SaveRefreshTokenToDB(ctx context.Context, token *models.CreateRefreshToken) error {
	const op = "storage.mongodb.SaveRefreshToken"

	coll := m.client.Database(m.dbname).Collection(CollTokens)
	_, err := coll.InsertOne(ctx, token)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("%s: %w", op, storage.ErrTokenExists)
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (m *MClient) GetExistChatID(ctx context.Context, userID primitive.ObjectID) (string, error) {
	const op = "storage.mongodb.GetExistChatID"

	coll := m.client.Database(m.dbname).Collection(CollAuth)

	filter := bson.M{"_id": userID}

	var chatID models.UserChatID
	err := coll.FindOne(ctx, filter).Decode(&chatID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return chatID.ChatID, nil
}
