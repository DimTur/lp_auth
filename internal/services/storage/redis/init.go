package redis

import (
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"
)

var (
	ErrCreateRedisClient = errors.New("error creating redis client")
)

type RedisClient struct {
	client *redis.Client
}

type RedisOpts struct {
	Host     string
	Port     int
	DB       int
	Password string
}

func NewRedisClient(ro RedisOpts) (*RedisClient, error) {
	const op = "storage.NewRedisClient"

	url := fmt.Sprintf("redis://:%s@%s:%d/%d", ro.Password, ro.Host, ro.Port, ro.DB)

	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("%s: %w - %v", op, ErrCreateRedisClient, err)
	}

	return &RedisClient{client: redis.NewClient(opts)}, nil
}
