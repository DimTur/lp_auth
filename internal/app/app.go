package app

import (
	"log/slog"
	"time"

	grpcapp "github.com/DimTur/lp_auth/internal/app/grpc"
	"github.com/DimTur/lp_auth/internal/services/auth"
	"github.com/DimTur/lp_auth/pkg/crypto"
	"github.com/DimTur/lp_auth/pkg/jwt"
	"github.com/go-playground/validator/v10"
)

type AuthStorage interface {
	auth.UserSaver
	auth.UserProvider
	auth.TokenProvider
}

type AuthRedis interface {
	auth.TokenRedisStore
}

type App struct {
	GRPCSrv *grpcapp.Server
}

func NewApp(
	authStorage AuthStorage,
	authRedis AuthRedis,
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
		authRedis,
		// &storage,
		passwordHasher,
		jwtManager,
	)

	grpcServer, err := grpcapp.NewGRPCServer(
		grpcAddr,
		authGRPCHandlers,
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
