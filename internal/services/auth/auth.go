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
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type UserSaver interface {
	SaveUser(ctx context.Context, user *models.DBCreateUser) error
}

type UserProvider interface {
	FindUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserRole(ctx context.Context, userID primitive.ObjectID) (string, error)
}

type TokenProvider interface {
	SaveRefreshToken(ctx context.Context, token *models.CreateRefreshToken) error
	DeleteRefreshToken(ctx context.Context, token string) error
	FindRefreshToken(ctx context.Context, userID primitive.ObjectID) (*models.RefreshToken, error)
}

type JWTManager interface {
	IssueAccessToken(userID primitive.ObjectID) (string, error)
	IssueRefreshToken(userID primitive.ObjectID) (string, error)
	VerifyToken(tokenString string) (*jwt.Token, error)
	GetRefreshExpiresIn() time.Duration
}

var (
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrInvalidAppID        = errors.New("invalid app id")
	ErrUserExists          = errors.New("user already exists")
	ErrUserNotFound        = errors.New("user not found")
	ErrAppExists           = errors.New("app already exists")
	ErrInvalidUserID       = errors.New("invalid user id")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrInvalidAccessToken  = errors.New("invalid access token")
)

type AuthHandlers struct {
	log            *slog.Logger
	validator      *validator.Validate
	usrSaver       UserSaver
	usrProvider    UserProvider
	tokenProvider  TokenProvider
	passwordHasher crypto.PasswordHasher
	jwtManager     JWTManager
}

// New returns a new instance of the Auth service.
func New(
	log *slog.Logger,
	validator *validator.Validate,
	userSaver UserSaver,
	userProvider UserProvider,
	tokenProvider TokenProvider,
	passwordHasher crypto.PasswordHasher,
	jwtManager JWTManager,
) *AuthHandlers {
	return &AuthHandlers{
		log:            log,
		validator:      validator,
		usrSaver:       userSaver,
		usrProvider:    userProvider,
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
) (*models.LogInTokens, error) {
	const op = "auth.LoginUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("username", email),
	)

	log.Info("attempting to login user")

	user, err := a.usrProvider.FindUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", slog.String("err", err.Error()))
			return &models.LogInTokens{}, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}

		a.log.Error("failed to get user", slog.String("err", err.Error()))
		return &models.LogInTokens{}, fmt.Errorf("%s: %w", op, err)
	}

	if !a.passwordHasher.ComparePassword(user.PassHash, password) {
		a.log.Info("invalid credentials")
		return &models.LogInTokens{}, fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

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
				return &models.LogInTokens{}, fmt.Errorf("%s: %w", op, ErrInvalidRefreshToken)
			}

			a.log.Error("failed to get refresh token", slog.String("err", err.Error()))
			return &models.LogInTokens{}, fmt.Errorf("%s: %w", op, err)
		}
	}

	// Generate new access token
	accessToken, err := a.jwtManager.IssueAccessToken(user.ID)
	if err != nil {
		a.log.Info("failed to generate access token", slog.String("err", err.Error()))
		return &models.LogInTokens{}, fmt.Errorf("%s: %w", op, err)
	}

	// Generate new refresh token
	refreshToken, err := a.jwtManager.IssueRefreshToken(user.ID)
	if err != nil {
		a.log.Info("failed to generate refresh token", slog.String("err", err.Error()))
		return &models.LogInTokens{}, fmt.Errorf("%s: %w", op, err)
	}

	// Write refresh token to DB
	refToken := &models.CreateRefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(a.jwtManager.GetRefreshExpiresIn()),
	}
	err = a.tokenProvider.SaveRefreshToken(ctx, refToken)
	if err != nil {
		a.log.Info("failed to save refresh token to database", slog.String("err", err.Error()))
		return &models.LogInTokens{}, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully")

	return &models.LogInTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// RegisterNewUser registers new user in the system and returns user ID.
//
// If user with given username already exists, returns error.
func (ah *AuthHandlers) RegisterUser(ctx context.Context, user models.CreateUser) error {
	const op = "auth.RegisterUser"

	log := ah.log.With(
		slog.String("op", op),
		slog.String("email", user.Email),
	)

	// Validation
	err := ah.validator.Struct(user)
	if err != nil {
		log.Warn("invalid parameters", slog.String("err", err.Error()))
		return fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	log.Info("registering user")

	passHash, err := ah.passwordHasher.HashPassword(user.Password)
	if err != nil {
		log.Error("failed to generate password hash", slog.String("err", err.Error()))
		return fmt.Errorf("%s: %w", op, err)
	}

	newUser := models.DBCreateUser{
		ID:       primitive.NewObjectID(),
		Email:    user.Email,
		PassHash: passHash,
		Name:     user.Name,
		Role:     models.UserRoleDefault,
		Created:  time.Now(),
		Updated:  time.Now(),
	}
	err = ah.usrSaver.SaveUser(ctx, &newUser)
	if err != nil {
		if errors.Is(err, storage.ErrUserExitsts) {
			ah.log.Warn("user already exists", slog.String("err", err.Error()))
			return fmt.Errorf("%s: %w", op, ErrUserExists)
		}

		log.Error("failed to save user", slog.String("err", err.Error()))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user registered in successfully")

	return nil
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

	userIDHex, ok := claims["sub"].(string)
	if !ok {
		log.Error("invalid userID claim")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	userID, err := primitive.ObjectIDFromHex(userIDHex)
	if err != nil {
		log.Error("invalid userID hex")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	accessToken, err := a.jwtManager.IssueAccessToken(userID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return accessToken, nil
}

// IsAdmin checks if user is admin.
func (a *AuthHandlers) IsAdmin(ctx context.Context, userID primitive.ObjectID) (bool, error) {
	const op = "auth.IsAdmin"

	log := a.log.With(
		slog.String("op", op),
		slog.String("user_id", userID.Hex()),
	)

	log.Info("check user is admin")

	role, err := a.usrProvider.GetUserRole(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", slog.String("err", err.Error()))
			return false, fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		return false, fmt.Errorf("%s: %w", op, err)
	}

	if role != models.UserRoleAdmin {
		log.Info("checked user is admin", slog.Bool("is_admin", false))
		return false, nil
	}

	log.Info("checked user is admin", slog.Bool("is_admin", true))

	return true, nil
}

func (a *AuthHandlers) AuthCheck(ctx context.Context, accessToken string) (*models.AuthCheck, error) {
	const op = "auth.AuthCheck"

	// TODO: find user by access token
	log := a.log.With(
		slog.String("op", op),
		// slog.String("user_id", userIDByToken),
	)

	log.Info("verifying access token")

	token, err := a.jwtManager.VerifyToken(accessToken)
	if err != nil {
		log.Error("token verification failed: %v", slog.String("err", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidAccessToken)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid || claims["type"] != "access" {
		log.Error("invalid token claims or type")
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidAccessToken)
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		log.Error("invalid subject claim")
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidAccessToken)
	}

	return &models.AuthCheck{
		IsValid: token.Valid,
		UserId:  userID,
	}, nil
}
