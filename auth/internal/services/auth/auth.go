package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/DimTur/learning_platform/auth/internal/domain/models"
	"github.com/DimTur/learning_platform/auth/internal/services/storage"
	"github.com/DimTur/learning_platform/auth/pkg/crypto"
	"github.com/DimTur/learning_platform/auth/pkg/jwt"
)

type AuthHandlers struct {
	log            *slog.Logger
	usrSaver       UserSaver
	usrProvider    UserProvider
	appProvider    AppProvider
	passwordHasher crypto.PasswordHasher
	jwtManager     *jwt.JWTManager
}

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

type AppProvider interface {
	FindAppByID(ctx context.Context, appID int64) (models.App, error)
	AddApp(
		ctx context.Context,
		name string,
		secret string,
	) (appID int64, err error)
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidAppID       = errors.New("invalid app id")
	ErrUserExists         = errors.New("user already exists")
)

// New returns a new instance of the Auth service.
func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	passwordHasher crypto.PasswordHasher,
	jwtManager *jwt.JWTManager,
) *AuthHandlers {
	return &AuthHandlers{
		log:            log,
		usrSaver:       userSaver,
		usrProvider:    userProvider,
		appProvider:    appProvider,
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
	appID int64,
) (string, error) {
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
			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		a.log.Error("failed to get user", slog.String("err", err.Error()))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	if !a.passwordHasher.ComparePassword(password, user.PassHash) {
		a.log.Info("invalid credentials", slog.String("err", err.Error()))
		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.FindAppByID(ctx, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			a.log.Warn("app not found", slog.String("err", err.Error()))
			return "", fmt.Errorf("%s: %w", op, ErrInvalidAppID)
		}

		a.log.Error("failed to get app", slog.String("err", err.Error()))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	token, err := a.jwtManager.IssueAccessToken(user.ID, app.ID)
	if err != nil {
		a.log.Info("failed to generate token", slog.String("err", err.Error()))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully")

	return token, nil
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
	return "", nil
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
	return 0, nil
}
