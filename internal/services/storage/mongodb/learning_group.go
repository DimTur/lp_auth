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
	CollLearningGroup = "learning_groups"
)

func (m *MClient) SaveLg(ctx context.Context, lg *models.DBCreateLearningGroup) error {
	const op = "storage.mongodb.SaveLg"

	coll := m.client.Database(m.dbname).Collection(CollLearningGroup)
	lg.ID = primitive.NewObjectID().Hex()
	_, err := coll.InsertOne(ctx, lg)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("%s: %w", op, storage.ErrLgExitsts)
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (m *MClient) GetLgByID(ctx context.Context, userLG *models.GetLgByID) (*models.LearningGroup, error) {
	const op = "storage.mongodb.GetLgByID"

	coll := m.client.Database(m.dbname).Collection(CollLearningGroup)

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.D{
			{Key: "_id", Value: userLG.LgId},
			{Key: "learners", Value: bson.D{{Key: "$in", Value: bson.A{userLG.UserID}}}},
		}}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: CollAuth},
			{Key: "localField", Value: "learners"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "learners"},
		}}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: CollAuth},
			{Key: "localField", Value: "group_admins"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "group_admins"},
		}}},
	}

	cursor, err := coll.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, storage.ErrLgNotFound)
	}
	defer cursor.Close(ctx)

	if !cursor.Next(ctx) {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	var lgDB models.DBLearningGroup
	if err := cursor.Decode(&lgDB); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	learners := make([]models.GroupUser, len(lgDB.Learners))
	for i, learner := range lgDB.Learners {
		learners[i] = models.GroupUser(learner)
	}

	groupAdmins := make([]models.GroupUser, len(lgDB.GroupAdmins))
	for i, admin := range lgDB.GroupAdmins {
		groupAdmins[i] = models.GroupUser(admin)
	}

	return &models.LearningGroup{
		ID:          lgDB.ID,
		Name:        lgDB.Name,
		CreatedBy:   lgDB.CreatedBy,
		ModifiedBy:  lgDB.ModifiedBy,
		Created:     lgDB.Created,
		Updated:     lgDB.Updated,
		Learners:    learners,
		GroupAdmins: groupAdmins,
	}, nil
}

func (m *MClient) GetLGroupsByUserID(ctx context.Context, userID string) ([]*models.LearningGroupShort, error) {
	const op = "storage.mongodb.GetLGroupsByUserID"

	coll := m.client.Database(m.dbname).Collection(CollLearningGroup)
	filter := bson.M{
		"learners": bson.M{
			"$in": []string{userID},
		},
	}

	cursor, err := coll.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, storage.ErrLgNotFound)
	}
	defer cursor.Close(ctx)

	var learningGroups []*models.LearningGroupShort
	if err := cursor.All(ctx, &learningGroups); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return learningGroups, nil
}

func (m *MClient) UpdateLgByID(ctx context.Context, lg *models.DBUpdateLearningGroup) error {
	const op = "storage.mongodb.UpdateLgByID"

	coll := m.client.Database(m.dbname).Collection(CollLearningGroup)

	update := bson.M{}
	addToSet := bson.M{}
	if lg.Name != "" {
		update["name"] = lg.Name
	}
	if lg.ModifiedBy != "" {
		update["modified_by"] = lg.ModifiedBy
	}
	if !lg.Updated.IsZero() {
		update["updated"] = lg.Updated
	}
	if len(lg.GroupAdmins) > 0 {
		addToSet["group_admins"] = bson.M{"$each": lg.GroupAdmins}
	}
	if len(lg.Learners) > 0 {
		addToSet["learners"] = bson.M{"$each": lg.Learners}
	}

	updateQuery := bson.M{}
	if len(update) > 0 {
		updateQuery["$set"] = update
	}
	if len(addToSet) > 0 {
		updateQuery["$addToSet"] = addToSet
	}

	if len(updateQuery) > 0 {
		_, err := coll.UpdateByID(ctx, lg.ID, updateQuery)
		if err != nil {
			if errors.Is(err, mongo.ErrNoDocuments) {
				return fmt.Errorf("%s: %w", op, storage.ErrLgNotFound)
			}
			return fmt.Errorf("%s: %w", op, err)
		}
	}

	return nil
}

func (m *MClient) DeleteLgByID(ctx context.Context, delG *models.DelGroup) error {
	const op = "storage.mongodb.DeleteLgByID"

	coll := m.client.Database(m.dbname).Collection(CollLearningGroup)
	filter := bson.M{"_id": delG.LgId}
	_, err := coll.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (m *MClient) IsGroupAdmin(ctx context.Context, lgUser *models.IsGroupAdmin) (bool, error) {
	const op = "storage.mongodb.IsGroupAdmin"

	coll := m.client.Database(m.dbname).Collection(CollLearningGroup)
	filter := bson.M{
		"_id": lgUser.LgId,
		"group_admins": bson.M{
			"$in": []string{lgUser.UserID},
		},
	}
	cursor, err := coll.Find(ctx, filter)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, storage.ErrLgNotFound)
	}
	defer cursor.Close(ctx)

	return true, nil
}

func (m *MClient) IsLearner(ctx context.Context, lgUser *models.GetLgByID) (bool, error) {
	const op = "storage.mongodb.IsLearner"

	coll := m.client.Database(m.dbname).Collection(CollLearningGroup)
	filter := bson.M{
		"_id": lgUser.LgId,
		"learners": bson.M{
			"$in": []string{lgUser.UserID},
		},
	}
	cursor, err := coll.Find(ctx, filter)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, storage.ErrLgNotFound)
	}
	defer cursor.Close(ctx)

	return true, nil
}

func (m *MClient) GetUserIsGroupAdminIn(ctx context.Context, user *models.UserIsGroupAdminIn) ([]string, error) {
	const op = "storage.mongodb.GetUserIsGroupAdminIn"

	coll := m.client.Database(m.dbname).Collection(CollLearningGroup)
	filter := bson.M{
		"group_admins": bson.M{
			"$in": []string{user.UserID},
		},
	}

	cursor, err := coll.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
	}
	defer cursor.Close(ctx)

	var groupIDs []string
	for cursor.Next(ctx) {
		var result struct {
			ID string `bson:"_id"`
		}
		if err := cursor.Decode(&result); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		groupIDs = append(groupIDs, result.ID)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return groupIDs, nil
}

func (m *MClient) GetUserIsLearnerIn(ctx context.Context, user *models.UserIsLearnerIn) ([]string, error) {
	const op = "storage.mongodb.GetUserIsLearnerIn"

	coll := m.client.Database(m.dbname).Collection(CollLearningGroup)
	filter := bson.M{
		"learners": bson.M{
			"$in": []string{user.UserID},
		},
	}

	cursor, err := coll.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
	}
	defer cursor.Close(ctx)

	var groupIDs []string
	for cursor.Next(ctx) {
		var result struct {
			ID string `bson:"_id"`
		}
		if err := cursor.Decode(&result); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		groupIDs = append(groupIDs, result.ID)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return groupIDs, nil
}

func (m *MClient) GetLearners(ctx context.Context, lgID *models.GetLearners) ([]string, error) {
	const op = "storage.mongodb.GetLearners"

	coll := m.client.Database(m.dbname).Collection(CollLearningGroup)

	filter := bson.D{{Key: "_id", Value: lgID.LgId}}
	var result struct {
		Learners []string `bson:"learners"`
	}

	// Выполняем запрос
	err := coll.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return result.Learners, nil
}
