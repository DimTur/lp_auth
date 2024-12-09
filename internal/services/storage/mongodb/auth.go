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
	user.ID = primitive.NewObjectID().Hex()
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

	var userDB models.DBUser
	err := coll.FindOne(ctx, filter).Decode(&userDB)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &models.User{
		ID:       userDB.ID,
		Email:    userDB.Email,
		PassHash: userDB.PassHash,
		Name:     userDB.Name,
		IsAdmin:  userDB.IsAdmin,
		TgLink:   userDB.TgLink,
		Created:  userDB.Created,
		Updated:  userDB.Updated,
	}, nil
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

		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &user, nil
}

func (m *MClient) UpdateUserInfo(ctx context.Context, userInfo *models.DBUpdateUserInfo) error {
	const op = "storage.mongodb.UpdateUserInfo"

	coll := m.client.Database(m.dbname).Collection(CollAuth)

	update := bson.M{}
	if userInfo.Email != "" {
		update["email"] = userInfo.Email
	}
	if userInfo.Name != "" {
		update["name"] = userInfo.Name
	}
	if userInfo.IsAdmin != nil {
		update["is_admin"] = userInfo.IsAdmin
	}
	if userInfo.TgLink != "" {
		update["tg_link"] = userInfo.TgLink
	}
	if userInfo.ChatID != "" {
		update["chat_id"] = userInfo.ChatID
	}
	if !userInfo.Updated.IsZero() {
		update["updated"] = userInfo.Updated
	}

	if len(update) > 0 {
		_, err := coll.UpdateByID(ctx, userInfo.ID, bson.M{
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

func (m *MClient) GetUserRoles(ctx context.Context, userID string) (*models.UserRoles, error) {
	const op = "storage.mongodb.GetUserRole"

	coll := m.client.Database(m.dbname).Collection(CollAuth)

	filter := bson.M{"_id": userID}

	var userRoles models.UserRoles
	err := coll.FindOne(ctx, filter).Decode(&userRoles)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &userRoles, nil
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

func (m *MClient) GetUsersInfoBatch(ctx context.Context, userIDs []string) ([]models.UserNotification, error) {
	const op = "storage.mongodb.GetUsersInfoBatch"

	coll := m.client.Database(m.dbname).Collection(CollAuth)
	filter := bson.M{
		"_id": bson.M{"$in": userIDs},
	}

	cursor, err := coll.Find(ctx, filter)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer cursor.Close(ctx)

	var users []models.UserNotification
	if err := cursor.All(ctx, &users); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return users, nil
}
