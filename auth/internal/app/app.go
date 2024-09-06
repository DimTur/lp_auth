package app

import (
	"log/slog"
	"time"

	grpcapp "github.com/DimTur/learning_platform/auth/internal/app/grpc"
	"github.com/DimTur/learning_platform/auth/internal/services/auth"
	"github.com/DimTur/learning_platform/auth/internal/services/storage/sqlite"
	"github.com/DimTur/learning_platform/auth/pkg/crypto"
	"github.com/DimTur/learning_platform/auth/pkg/jwt"
)

type App struct {
	GRPCSrv *grpcapp.Server
}

func NewApp(
	storage sqlite.SQLLiteStorage,
	jwtIssuer string,
	jwtAccessExpiresIn time.Duration,
	jwtRefreshExpiresIn time.Duration,
	jwtPublicKey string,
	jwtPrivetKey string,
	grpcAddr string,

	logger *slog.Logger,
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
		&storage,
		&storage,
		&storage,
		&storage,
		passwordHasher,
		jwtManager,
	)
	grpcServer, err := grpcapp.NewGRPCServer(
		grpcAddr,
		authGRPCHandlers,
		logger,
	)
	if err != nil {
		return nil, err
	}

	return &App{
		GRPCSrv: grpcServer,
	}, nil
}
