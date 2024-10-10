package config

import (
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	GRPCServer GRPCServer `yaml:"grpc_server"`
	Storage    MongoDB    `yaml:"mongo_db"`
	JWT        JWT        `yaml:"jwt"`
}

type GRPCServer struct {
	Address string `yaml:"address" env-default:":9090"`
}

type MongoDB struct {
	DbName   string `yaml:"db_name"`
	UserName string `yaml:"username"`
	Password string `yaml:"password"`
}

type JWT struct {
	Issuer           string        `yaml:"issuer"`
	AccessExpiresIn  time.Duration `yaml:"access_expires_in"`
	RefreshExpiresIn time.Duration `yaml:"refresh_expires_in"`
	PublicKey        string        `yaml:"public_key"`
	PrivateKey       string        `yaml:"private_key"`
	PublicKeyTest    string        `yaml:"public_key_test"`
	PrivateKeyTest   string        `yaml:"private_key_test"`
}

func Parse(s string) (*Config, error) {
	c := &Config{}
	if err := cleanenv.ReadConfig(s, c); err != nil {
		return nil, err
	}

	privateKey, err := os.ReadFile(c.JWT.PrivateKey)
	if err != nil {
		return nil, err
	}
	publicKey, err := os.ReadFile(c.JWT.PublicKey)
	if err != nil {
		return nil, err
	}
	c.JWT.PrivateKey = string(privateKey)
	c.JWT.PublicKey = string(publicKey)
	c.JWT.PrivateKeyTest = string(privateKey)
	c.JWT.PublicKeyTest = string(publicKey)

	return c, nil
}
