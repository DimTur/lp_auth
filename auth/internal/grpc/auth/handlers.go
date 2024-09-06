package auth

import (
	"context"
	"errors"

	"github.com/DimTur/learning_platform/auth/internal/services/auth"
	"github.com/DimTur/learning_platform/auth/internal/services/storage"
	"github.com/DimTur/learning_platform/auth/internal/utils/validator"
	ssov1 "github.com/DimTur/learning_platform/auth/pkg/server/grpc/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthHandlers interface {
	LoginUser(
		ctx context.Context,
		email string,
		password string,
		appID string,
	) (token string, err error)
	RegisterUser(
		ctx context.Context,
		email string,
		password string,
	) (userID string, err error)
	RefreshToken(ctx context.Context, refreshToken string) (accessToken string, err error)
	IsAdmin(ctx context.Context, userID string) (bool, error)
	AddApp(
		ctx context.Context,
		name string,
		secret string,
	) (appID string, err error)
}

type serverAPI struct {
	auth AuthHandlers

	ssov1.UnimplementedAuthServer
}

func RegisterAuthServiceServer(gRPC *grpc.Server, auth AuthHandlers) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) LoginUser(ctx context.Context, req *ssov1.LoginUserRequest) (*ssov1.LoginUserResponse, error) {
	if err := validator.ValidateLogin(req); err != nil {
		return nil, err
	}

	token, err := s.auth.LoginUser(ctx, req.GetEmail(), req.GetPassword(), req.GetAppId())
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.LoginUserResponse{
		AccessToken: token,
	}, nil
}

func (s *serverAPI) RegisterUser(ctx context.Context, req *ssov1.RegisterUserRequest) (*ssov1.RegisterUserResponse, error) {
	if err := validator.ValidateRegister(req); err != nil {
		return nil, err
	}

	userID, err := s.auth.RegisterUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.RegisterUserResponse{
		UserId: userID,
	}, nil
}

func (s *serverAPI) RefreshToken(ctx context.Context, req *ssov1.RefreshTokenRequest) (*ssov1.RefreshTokenResponse, error) {
	return &ssov1.RefreshTokenResponse{}, nil
}

func (s *serverAPI) IsAdmin(ctx context.Context, req *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	if err := validator.ValidateIsAdmin(req); err != nil {
		return nil, err
	}

	isAdmin, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, status.Error(codes.AlreadyExists, "user not found")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil
}

func (s *serverAPI) AddApp(ctx context.Context, req *ssov1.AddAppRequest) (*ssov1.AddAppResponse, error) {
	return &ssov1.AddAppResponse{}, nil
}