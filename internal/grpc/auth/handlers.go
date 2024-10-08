package auth

import (
	"context"
	"errors"

	"github.com/DimTur/lp_auth/internal/services/auth"
	"github.com/DimTur/lp_auth/internal/services/storage"
	"github.com/DimTur/lp_auth/internal/utils/validator"
	ssov1 "github.com/DimTur/lp_protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthHandlers interface {
	LoginUser(
		ctx context.Context,
		email string,
		password string,
	) (resp ssov1.LoginUserResponse, err error)
	RegisterUser(
		ctx context.Context,
		email string,
		password string,
	) (userID int64, err error)
	RefreshToken(ctx context.Context, refreshToken string) (accessToken string, err error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
	AddApp(
		ctx context.Context,
		name string,
		secret string,
	) (appID int64, err error)
	AuthCheck(ctx context.Context, accessToken string) (resp *ssov1.AuthCheckResponse, err error)
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

	tokens, err := s.auth.LoginUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			return nil, status.Error(codes.Unauthenticated, "invalid email or password")
		case errors.Is(err, auth.ErrInvalidAppID):
			return nil, status.Error(codes.InvalidArgument, "invalid app_id")
		case errors.Is(err, auth.ErrUserNotFound):
			return nil, status.Error(codes.NotFound, "user not found")
		case errors.Is(err, auth.ErrInvalidRefreshToken):
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		case errors.Is(err, auth.ErrInvalidRefreshToken):
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.LoginUserResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
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
	if err := validator.ValidateRefreshToken(req); err != nil {
		return nil, err
	}

	accessToken, err := s.auth.RefreshToken(ctx, req.GetRefreshToken())
	if err != nil {
		if errors.Is(err, auth.ErrInvalidRefreshToken) {
			return nil, status.Error(codes.InvalidArgument, "wrong token")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.RefreshTokenResponse{
		AccessToken: accessToken,
	}, nil
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
	if err := validator.ValidateApp(req); err != nil {
		return nil, err
	}

	appID, err := s.auth.AddApp(ctx, req.GetName(), req.GetSecret())
	if err != nil {
		if errors.Is(err, auth.ErrAppExists) {
			return nil, status.Error(codes.InvalidArgument, "app already exists")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.AddAppResponse{
		AppId: appID,
	}, nil
}

func (s *serverAPI) AuthCheck(ctx context.Context, req *ssov1.AuthCheckRequest) (*ssov1.AuthCheckResponse, error) {
	resp, err := s.auth.AuthCheck(ctx, req.GetAccessToken())
	if err != nil {
		if errors.Is(err, auth.ErrInvalidAccessToken) {
			return nil, status.Error(codes.Unauthenticated, "unauth")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return resp, nil
}
