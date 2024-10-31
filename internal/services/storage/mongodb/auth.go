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
	user.ID = primitive.NewObjectID()
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
	objid, err := primitive.ObjectIDFromHex(userInfo.ID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, storage.ErrObjectID)
	}

	update := bson.M{}
	if userInfo.Email != "" {
		update["email"] = userInfo.Email
	}
	if userInfo.Name != "" {
		update["name"] = userInfo.Name
	}
	if userInfo.TgLink != "" {
		update["tg_link"] = userInfo.TgLink
	}
	if !userInfo.Updated.IsZero() {
		update["updated"] = userInfo.Updated
	}

	if len(update) > 0 {
		_, err = coll.UpdateByID(ctx, objid, bson.M{
			"$set": update,
		})
		if err != nil {
			if errors.Is(err, mongo.ErrNoDocuments) {
				return fmt.Errorf("%s: %w", op, storage.ErrInvalidCredentials)
			}
			return fmt.Errorf("%s: %w", op, err)
		}
	}

	return nil
}

func (m *MClient) GetUserRole(ctx context.Context, userID string) (string, error) {
	const op = "storage.mongodb.GetUserRole"

	coll := m.client.Database(m.dbname).Collection(CollAuth)
	objid, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, storage.ErrObjectID)
	}

	filter := bson.M{"_id": objid}

	var userRole models.UserRole
	err = coll.FindOne(ctx, filter).Decode(&userRole)
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

func (m *MClient) GetExistChatID(ctx context.Context, userID string) (string, error) {
	const op = "storage.mongodb.GetExistChatID"

	coll := m.client.Database(m.dbname).Collection(CollAuth)
	objid, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, storage.ErrObjectID)
	}
	filter := bson.M{"_id": objid}

	var chatID models.UserChatID
	err = coll.FindOne(ctx, filter).Decode(&chatID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return chatID.ChatID, nil
}
