package mongodb

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

var (
	ErrCreateMongoClient     = errors.New("error creating mongo client")
	ErrDisconnectMongoClient = errors.New("smth went wrong with close db conn")
)

type MClient struct {
	client *mongo.Client
	dbname string
}

func NewMongoClient(ctx context.Context, url string, dbname string) (*MClient, error) {
	const op = "storage.NewMongoClient"

	var cl MClient

	client, err := mongo.Connect(options.Client().ApplyURI(url))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, ErrCreateMongoClient)
	}

	cl.client = client
	cl.dbname = dbname

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, ErrCreateMongoClient)
	}

	return &cl, nil
}

func (m *MClient) Close(ctx context.Context) error {
	const op = "storage.MClient.Disconnect"

	if err := m.client.Disconnect(ctx); err != nil {
		return fmt.Errorf("%s: %w", op, ErrDisconnectMongoClient)
	}
	return nil
}
