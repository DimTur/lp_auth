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

func (m *MClient) GetLgByID(ctx context.Context, id string) (*models.LearningGroup, error) {
	const op = "storage.mongodb.GetLgByID"

	coll := m.client.Database(m.dbname).Collection(CollLearningGroup)

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.D{{Key: "_id", Value: id}}}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: CollAuth},
			{Key: "localField", Value: "learners"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "learners"},
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

	return &models.LearningGroup{
		ID:         lgDB.ID,
		Name:       lgDB.Name,
		CreatedBy:  lgDB.CreatedBy,
		ModifiedBy: lgDB.ModifiedBy,
		Created:    lgDB.Created,
		Updated:    lgDB.Updated,
		Learners:   learners,
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
		update["group_admins"] = lg.GroupAdmins
	}
	if len(lg.Learners) > 0 {
		update["learners"] = lg.Learners
	}

	if len(update) > 0 {
		_, err := coll.UpdateByID(ctx, lg.ID, bson.M{
			"$set": update,
		})
		if err != nil {
			if errors.Is(err, mongo.ErrNoDocuments) {
				return fmt.Errorf("%s: %w", op, storage.ErrLgNotFound)
			}
			return fmt.Errorf("%s: %w", op, err)
		}
	}

	return nil
}

func (m *MClient) DeleteLgByID(ctx context.Context, id string) error {
	const op = "storage.mongodb.DeleteLgByID"

	coll := m.client.Database(m.dbname).Collection(CollLearningGroup)
	objid, _ := primitive.ObjectIDFromHex(id)
	filter := bson.M{"_id": objid}
	_, err := coll.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
