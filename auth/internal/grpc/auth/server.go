package auth

import (
	"context"
	"errors"

	ssov1 "github.com/DimTur/learning_platform/auth/gen/go/sso"
	"github.com/DimTur/learning_platform/auth/internal/services/auth"
	"github.com/DimTur/learning_platform/auth/internal/services/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		appID string,
	) (token string, err error)
	RegisterNewUser(
		ctx context.Context,
		email string,
		password string,
	) (userID string, err error)
	IsAdmin(ctx context.Context, userID string) (bool, error)
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	if err := validateLogin(req); err != nil {
		return nil, err
	}

	token, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword(), req.GetAppId())
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.LoginResponse{
		Token: token,
	}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	if err := validateRegister(req); err != nil {
		return nil, err
	}

	userID, err := s.auth.RegisterNewUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.RegisterResponse{
		UserId: userID,
	}, nil
}

func (s *serverAPI) IsAdmin(ctx context.Context, req *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	if err := validateIsAdmin(req); err != nil {
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

func validateLogin(req *ssov1.LoginRequest) error {
	// TODO: use for validation special package
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email is requered")
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is requered")
	}

	if req.GetAppId() == "" {
		return status.Error(codes.InvalidArgument, "app_id is requered")
	}

	return nil
}

func validateRegister(req *ssov1.RegisterRequest) error {
	// TODO: use for validation special package
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email is requered")
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is requered")
	}

	return nil
}

func validateIsAdmin(req *ssov1.IsAdminRequest) error {
	// TODO: use for validation special package
	if req.GetUserId() == "" {
		return status.Error(codes.InvalidArgument, "userID is requered")
	}

	return nil
}
