package config

import (
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	GRPCServer GRPCServer `yaml:"grpc_server"`
	Storage    Storage    `yaml:"storage"`
	JWT        JWT        `yaml:"jwt"`
}

type GRPCServer struct {
	Address string `yaml:"address" env-default:":9090"`
}

type Storage struct {
	SQLitePath string `yaml:"path" env-default:"db.sql"`
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

// import (
// 	"flag"
// 	"os"
// 	"time"

// 	"github.com/ilyakaznacheev/cleanenv"
// )

// type Config struct {
// 	Env         string        `yaml:"env" env-default:"local"`
// 	StoragePath string        `yaml:"storage_path" env-required:"true"`
// 	TokenTTL    time.Duration `yaml:"token_ttl" env-required:"true"`
// 	GRPC        GRPCConfig    `yaml:"grpc"`
// }

// type GRPCConfig struct {
// 	Port    int           `yaml:"port"`
// 	Timeout time.Duration `yaml:"timeout"`
// }

// func Parce() (*Config, error) {
// 	path := fetchConfigPath()
// 	if path == "" {
// 		panic("config path is empty")
// 	}

// 	if _, err := os.Stat(path); os.IsNotExist(err) {
// 		panic("config file does not exist: " + path)
// 	}

// 	var cfg Config

// 	if err := cleanenv.ReadConfig(path, &cfg); err != nil {
// 		panic("failed to read config: " + err.Error())
// 	}

// 	return &cfg, nil
// }

// // fetchConfigPath fetches config path from command line flag or enviroment variable.
// // Priority: flag > env > default.
// // Default: value is emty string.
// func fetchConfigPath() string {
// 	var res string

// 	flag.StringVar(&res, "config", "", "path to config file")
// 	flag.Parse()

// 	if res == "" {
// 		res = os.Getenv("CONFIG_PATH")
// 	}

// 	return res
// }
