package ssohandlers

import (
	"context"
	"errors"

	"github.com/DimTur/lp_auth/internal/domain/models"
	"github.com/DimTur/lp_auth/internal/services/auth"
	"github.com/DimTur/lp_auth/internal/services/storage"
	"github.com/DimTur/lp_auth/internal/utils/validator"
	ssov1 "github.com/DimTur/lp_protos/gen/go/sso"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *serverAPI) LoginUser(ctx context.Context, req *ssov1.LoginUserRequest) (*ssov1.LoginUserResponse, error) {
	if err := validator.ValidateLogin(req); err != nil {
		return nil, err
	}

	tokens, err := s.auth.LoginUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			return nil, status.Error(codes.Unauthenticated, "invalid email or password")
		case errors.Is(err, auth.ErrUserNotFound):
			return nil, status.Error(codes.NotFound, "user not found")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.LoginUserResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (s *serverAPI) LoginViaTg(ctx context.Context, req *ssov1.LoginViaTgRequest) (*ssov1.LoginViaTgResponse, error) {
	login := &models.LogInViaTg{
		Email: req.GetEmail(),
	}

	if err := s.auth.LogInViaTg(ctx, login); err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			return nil, status.Error(codes.InvalidArgument, "invalid email")
		case errors.Is(err, auth.ErrUserNotFound):
			return nil, status.Error(codes.NotFound, "user not found")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.LoginViaTgResponse{
		Success: true,
		Info:    "checks OTP code in tg bot",
	}, nil
}

func (s *serverAPI) CheckOTPAndLogIn(ctx context.Context, req *ssov1.CheckOTPAndLogInRequest) (*ssov1.CheckOTPAndLogInResponse, error) {
	otp := &models.LoginUserOTP{
		Email: req.GetEmail(),
		Code:  req.GetCode(),
	}

	tokens, err := s.auth.CheckOTP(ctx, otp)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		case errors.Is(err, auth.ErrUserNotFound):
			return nil, status.Error(codes.NotFound, "user not found")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.CheckOTPAndLogInResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (s *serverAPI) UpdateUserInfo(ctx context.Context, req *ssov1.UpdateUserInfoRequest) (*ssov1.UpdateUserInfoResponse, error) {
	userInfo := &models.UpdateUserInfo{
		ID:      req.GetId(),
		Email:   req.GetEmail(),
		Name:    req.GetName(),
		TgLink:  req.GetTgLink(),
		IsAdmin: req.GetIsAdmin(),
	}

	if err := s.auth.UpdateUserInfo(ctx, userInfo); err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			return nil, status.Error(codes.InvalidArgument, "invalid email")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.UpdateUserInfoResponse{
		Success: true,
	}, nil
}

func (s *serverAPI) RegisterUser(ctx context.Context, req *ssov1.RegisterUserRequest) (*ssov1.RegisterUserResponse, error) {
	if err := validator.ValidateRegister(req); err != nil {
		return nil, err
	}

	user := models.CreateUser{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
		Name:     req.GetName(),
	}
	err := s.auth.RegisterUser(ctx, user)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrUserExists):
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		case errors.Is(err, auth.ErrInvalidCredentials):
			return nil, status.Error(codes.InvalidArgument, "invalid credentinals")
		default:
			return nil, status.Error(codes.Internal, "internal error")
		}
	}

	return &ssov1.RegisterUserResponse{
		Success: true,
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

func (s *serverAPI) AuthCheck(ctx context.Context, req *ssov1.AuthCheckRequest) (*ssov1.AuthCheckResponse, error) {
	resp, err := s.auth.AuthCheck(ctx, req.GetAccessToken())
	if err != nil {
		if errors.Is(err, auth.ErrInvalidAccessToken) {
			return nil, status.Error(codes.Unauthenticated, "unauth")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.AuthCheckResponse{
		IsValid: resp.IsValid,
		UserId:  resp.UserId,
	}, nil
}
