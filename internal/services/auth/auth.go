package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/DimTur/lp_auth/internal/domain/models"
	"github.com/DimTur/lp_auth/internal/services/storage"
	"github.com/DimTur/lp_auth/pkg/crypto"
	ssov1 "github.com/DimTur/lp_protos/gen/go/sso"
	"github.com/golang-jwt/jwt/v5"
)

type UserSaver interface {
	SaveUser(
		ctx context.Context,
		email string,
		passHash []byte,
	) (uid int64, err error)
}

type UserProvider interface {
	FindUserByEmail(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type TokenProvider interface {
	SaveRefreshToken(ctx context.Context, userID int64, token string, expiresAt time.Time) error
	DeleteRefreshToken(ctx context.Context, token string) error
	FindRefreshToken(ctx context.Context, userID int64) (models.RefreshToken, error)
}

type AppProvider interface {
	FindAppByID(ctx context.Context, appID int64) (models.App, error)
	AddApp(
		ctx context.Context,
		name string,
		secret string,
	) (appID int64, err error)
}

type JWTManager interface {
	IssueAccessToken(userID int64) (string, error)
	IssueRefreshToken(userID int64) (string, error)
	VerifyToken(tokenString string) (*jwt.Token, error)
	GetRefreshExpiresIn() time.Duration
}

var (
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrInvalidAppID        = errors.New("invalid app id")
	ErrUserExists          = errors.New("user already exists")
	ErrAppExists           = errors.New("app already exists")
	ErrInvalidUserID       = errors.New("invalid user id")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
)

type AuthHandlers struct {
	log            *slog.Logger
	usrSaver       UserSaver
	usrProvider    UserProvider
	appProvider    AppProvider
	tokenProvider  TokenProvider
	passwordHasher crypto.PasswordHasher
	jwtManager     JWTManager
}

// New returns a new instance of the Auth service.
func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenProvider TokenProvider,
	passwordHasher crypto.PasswordHasher,
	jwtManager JWTManager,
) *AuthHandlers {
	return &AuthHandlers{
		log:            log,
		usrSaver:       userSaver,
		usrProvider:    userProvider,
		appProvider:    appProvider,
		tokenProvider:  tokenProvider,
		passwordHasher: passwordHasher,
		jwtManager:     jwtManager,
	}
}

// Login checks if user with given credentials exists in the system.
//
// If user exists, but password is incorrect, returns error.
// If user doesn't exist, returns error.
func (a *AuthHandlers) LoginUser(
	ctx context.Context,
	email string,
	password string,
) (ssov1.LoginUserResponse, error) {
	const op = "auth.LoginUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("username", email),
	)

	log.Info("attemting to login user")

	user, err := a.usrProvider.FindUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", slog.String("err", err.Error()))
			return ssov1.LoginUserResponse{}, fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		a.log.Error("failed to get user", slog.String("err", err.Error()))
		return ssov1.LoginUserResponse{}, fmt.Errorf("%s: %w", op, err)
	}

	if !a.passwordHasher.ComparePassword(user.PassHash, password) {
		a.log.Info("invalid credentials")
		return ssov1.LoginUserResponse{}, fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	// app, err := a.appProvider.FindAppByID(ctx, appID)
	// if err != nil {
	// 	if errors.Is(err, storage.ErrAppNotFound) {
	// 		a.log.Warn("app not found", slog.String("err", err.Error()))
	// 		return ssov1.LoginUserResponse{}, fmt.Errorf("%s: %w", op, ErrInvalidAppID)
	// 	}

	// 	a.log.Error("failed to get app", slog.String("err", err.Error()))
	// 	return ssov1.LoginUserResponse{}, fmt.Errorf("%s: %w", op, err)
	// }

	// Checks refresh token
	existingRefreshToken, err := a.tokenProvider.FindRefreshToken(ctx, user.ID)
	if err != nil {
		if errors.Is(err, storage.ErrTokenNotFound) {
			a.log.Warn("refresh token not found", slog.String("err", err.Error()))
		}

		a.log.Error("failed to get refresh token", slog.String("err", err.Error()))
	}

	// Delete refresh token
	if existingRefreshToken.Token != "" {
		err = a.tokenProvider.DeleteRefreshToken(ctx, existingRefreshToken.Token)
		if err != nil {
			if errors.Is(err, storage.ErrTokenNotFound) {
				a.log.Warn("refresh token not found", slog.String("err", err.Error()))
				return ssov1.LoginUserResponse{}, fmt.Errorf("%s: %w", op, ErrInvalidRefreshToken)
			}

			a.log.Error("failed to get refresh token", slog.String("err", err.Error()))
			return ssov1.LoginUserResponse{}, fmt.Errorf("%s: %w", op, err)
		}
	}

	// Generate new acccess token
	accessToken, err := a.jwtManager.IssueAccessToken(user.ID)
	if err != nil {
		a.log.Info("failed to generate access token", slog.String("err", err.Error()))
		return ssov1.LoginUserResponse{}, fmt.Errorf("%s: %w", op, err)
	}

	// Generate new refresh token
	refreshToken, err := a.jwtManager.IssueRefreshToken(user.ID)
	if err != nil {
		a.log.Info("failed to generate refresh token", slog.String("err", err.Error()))
		return ssov1.LoginUserResponse{}, fmt.Errorf("%s: %w", op, err)
	}

	// Write refresh token to DB
	err = a.tokenProvider.SaveRefreshToken(ctx, user.ID, refreshToken, time.Now().Add(a.jwtManager.GetRefreshExpiresIn()))
	if err != nil {
		a.log.Info("failed to save refresh token to database", slog.String("err", err.Error()))
		return ssov1.LoginUserResponse{}, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully")

	return ssov1.LoginUserResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// RegisterNewUser registers new user in the system and returns user ID.
//
// If user with given username already exists, returns error.
func (a *AuthHandlers) RegisterUser(ctx context.Context, email string, password string) (int64, error) {
	const op = "auth.RegisterUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("registering user")

	passHash, err := a.passwordHasher.HashPassword(password)
	if err != nil {
		log.Error("failed to generate password hash", slog.String("err", err.Error()))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.usrSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExitsts) {
			a.log.Warn("user already exists", slog.String("err", err.Error()))
			return 0, fmt.Errorf("%s: %w", op, ErrUserExists)
		}

		log.Error("failed to save user", slog.String("err", err.Error()))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (a *AuthHandlers) RefreshToken(ctx context.Context, refreshToken string) (string, error) {
	const op = "auth.RefreshToken"

	// TODO: find user by refresh token
	log := a.log.With(
		slog.String("op", op),
		// slog.String("user_id", userIDByToken),
	)

	log.Info("changing access token")

	token, err := a.jwtManager.VerifyToken(refreshToken)
	if err != nil {
		log.Error("token verification failed: %v", slog.String("err", err.Error()))
		return "", fmt.Errorf("%s: %w", op, ErrInvalidRefreshToken)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid || claims["type"] != "refresh" {
		log.Error("invalid token claims or type")
		return "", fmt.Errorf("%s: %w", op, ErrInvalidRefreshToken)
	}

	userIDFloat, ok := claims["sub"].(float64)
	if !ok {
		log.Error("invalid userID claim")
		return "", fmt.Errorf("%s: %w", op, err)
	}
	userID := int64(userIDFloat)

	accessToken, err := a.jwtManager.IssueAccessToken(userID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return accessToken, nil
}

// IsAdmin checks if user is admin.
func (a *AuthHandlers) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "auth.IsAdmin"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)

	log.Info("registering user")

	isAdmin, err := a.usrProvider.IsAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			a.log.Warn("user not found", slog.String("err", err.Error()))
			return false, fmt.Errorf("%s: %w", op, ErrInvalidAppID)
		}

		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checked if user is admin", slog.Bool("is_admin", isAdmin))

	return isAdmin, nil
}

func (a *AuthHandlers) AddApp(ctx context.Context, name string, secret string) (int64, error) {
	const op = "auth.RegisterUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("name", name),
	)

	log.Info("registering app")

	id, err := a.appProvider.AddApp(ctx, name, secret)
	if err != nil {
		if errors.Is(err, storage.ErrAppExists) {
			a.log.Warn("app already exists", slog.String("err", err.Error()))
			return 0, fmt.Errorf("%s: %w", op, ErrAppExists)
		}

		log.Error("failed to save app", slog.String("err", err.Error()))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}
