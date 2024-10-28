package config

import (
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	GRPCServer GRPCServer `yaml:"grpc_server"`
	Storage    MongoDB    `yaml:"mongo_db"`
	Redis      Redis      `yaml:"redis"`
	RabbitMQ   RabbitMQ   `yaml:"rabbit_mq"`
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

type Redis struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	TokenDB  int    `yaml:"token_db"`
	OtpDB    int    `yaml:"otp_db"`
	Password string `yaml:"password"`
}

type RabbitMQ struct {
	UserName      string      `yaml:"username"`
	Password      string      `yaml:"password"`
	Host          string      `yaml:"host"`
	Port          int         `yaml:"port"`
	OTPExchange   OTPExchange `yaml:"otp_exchange"`
	OTPQueue      OTPQueue    `yaml:"otp_queue"`
	OTPRoutingKey string      `yaml:"otp_routing_key"`
}

type OTPExchange struct {
	Name        string       `yaml:"name"`
	Kind        string       `yaml:"kind"`
	Durable     bool         `yaml:"durable"`
	AutoDeleted bool         `yaml:"auto_deleted"`
	Internal    bool         `yaml:"internal"`
	NoWait      bool         `yaml:"no_wait"`
	Args        ExchangeArgs `yaml:"args"`
}

type ExchangeArgs struct {
	AltExchange string `yaml:"alternate_exchange"`
}

type OTPQueue struct {
	Name        string    `yaml:"name"`
	Durable     bool      `yaml:"durable"`
	AutoDeleted bool      `yaml:"auto_deleted"`
	Exclusive   bool      `yaml:"exclusive"`
	NoWait      bool      `yaml:"no_wait"`
	Args        QueueArgs `yaml:"args"`
}

type QueueArgs struct {
	XMessageTtl int32 `yaml:"x_message_ttl"`
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

func (e ExchangeArgs) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"alternate-exchange": e.AltExchange,
	}
}

func (q QueueArgs) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"x-message-ttl": q.XMessageTtl,
	}
}
