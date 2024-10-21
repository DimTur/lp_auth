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

const CollAuth = "auth"

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
	fmt.Printf("Filter: %v\n", filter)

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

func (m *MClient) GetUserRole(ctx context.Context, userID primitive.ObjectID) (string, error) {
	const op = "storage.mongodb.GetUserRole"

	coll := m.client.Database(m.dbname).Collection(CollAuth)

	filter := bson.M{"_id": userID}
	fmt.Printf("Filter: %v\n", filter)

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

	coll := m.client.Database(m.dbname).Collection("tokens")
	_, err := coll.InsertOne(ctx, token)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("%s: %w", op, storage.ErrTokenExists)
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// func (m *MClient) FindRefreshToken(ctx context.Context, userID primitive.ObjectID) (*models.RefreshToken, error) {
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
