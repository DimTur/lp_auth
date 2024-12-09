package app

import (
	"log/slog"
	"time"

	grpcapp "github.com/DimTur/lp_auth/internal/app/grpc"
	"github.com/DimTur/lp_auth/internal/services/auth"
	learninggroup "github.com/DimTur/lp_auth/internal/services/learning_group"
	"github.com/DimTur/lp_auth/pkg/crypto"
	"github.com/DimTur/lp_auth/pkg/jwt"
	"github.com/go-playground/validator/v10"
)

type AuthStorage interface {
	auth.UserSaver
	auth.UserProvider
	auth.TokenProvider
}

type GroupStorage interface {
	learninggroup.GroupSaver
	learninggroup.GroupeProvider
	learninggroup.GroupeDel
}

type TokenRedis interface {
	auth.TokenRedisStore
}

type OTPRedis interface {
	auth.OTPRedisStore
}

type AuthRabbitMq interface {
	auth.RabbitMQQueues
}

type App struct {
	GRPCSrv *grpcapp.Server
}

func NewApp(
	authStorage AuthStorage,
	groupStorage GroupStorage,
	tokenRedis TokenRedis,
	otpRedis OTPRedis,
	authRabbitMq AuthRabbitMq,
	jwtIssuer string,
	jwtAccessExpiresIn time.Duration,
	jwtRefreshExpiresIn time.Duration,
	jwtPublicKey string,
	jwtPrivetKey string,
	grpcAddr string,

	logger *slog.Logger,
	validator *validator.Validate,
) (*App, error) {
	passwordHasher := crypto.NewPasswordHasher()
	jwtManager, err := jwt.NewJWTManager(
		jwtIssuer,
		jwtAccessExpiresIn,
		jwtRefreshExpiresIn,
		[]byte(jwtPublicKey),
		[]byte(jwtPrivetKey),
	)
	if err != nil {
		return nil, err
	}

	authGRPCHandlers := auth.New(
		logger,
		validator,
		authStorage,
		authStorage,
		authStorage,
		tokenRedis,
		otpRedis,
		authRabbitMq,
		passwordHasher,
		jwtManager,
	)

	lgGRPCHandlers := learninggroup.New(
		logger,
		validator,
		groupStorage,
		groupStorage,
		groupStorage,
		authRabbitMq,
	)

	grpcServer, err := grpcapp.NewGRPCServer(
		grpcAddr,
		authGRPCHandlers,
		lgGRPCHandlers,
		logger,
		validator,
	)
	if err != nil {
		return nil, err
	}

	return &App{
		GRPCSrv: grpcServer,
	}, nil
}
