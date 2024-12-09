package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/DimTur/lp_auth/internal/domain/models"
	"github.com/DimTur/lp_auth/internal/services/rabbitmq"
	"github.com/DimTur/lp_auth/internal/services/storage"
	"github.com/DimTur/lp_auth/internal/services/storage/redis"
	"github.com/DimTur/lp_auth/internal/utils/otp"
	"github.com/DimTur/lp_auth/pkg/crypto"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
)

const (
	exchangeOTP   = "otp"
	queueOTP      = "otp"
	otpRoutingKey = "otp"
)

type UserSaver interface {
	SaveUser(ctx context.Context, user *models.DBCreateUser) error
	UpdateUserInfo(ctx context.Context, userInfo *models.DBUpdateUserInfo) error
}

type UserProvider interface {
	FindUserByEmail(ctx context.Context, email string) (*models.User, error)
	FindUserByTgLink(ctx context.Context, tgLink string) (*models.User, error)
	GetUserRoles(ctx context.Context, userID string) (*models.UserRoles, error)
	GetExistChatID(ctx context.Context, userID string) (string, error)
	GetUsersInfoBatch(ctx context.Context, userIDs []string) ([]models.UserNotification, error)
}

type TokenProvider interface {
	SaveRefreshTokenToDB(ctx context.Context, token *models.CreateRefreshToken) error
}

type TokenRedisStore interface {
	SaveRefreshTokenToRedis(ctx context.Context, token *redis.CreateRefreshToken) error
	FindRefreshToken(ctx context.Context, userID string) (*redis.RefreshTokenFromRedis, error)
}

type OTPRedisStore interface {
	SaveOTPToRedis(ctx context.Context, otp *redis.CreateOTP) error
	FindOTPCode(ctx context.Context, code string) (*redis.UserOTPFromRedis, error)
	DeleteUserOTP(ctx context.Context, code string) error
}

type RabbitMQQueues interface {
	Publish(ctx context.Context, exchange, routingKey string, body []byte) error
	PublishToQueue(ctx context.Context, queueName string, body []byte) error
}

type JWTManager interface {
	IssueAccessToken(userID string) (string, error)
	IssueRefreshToken(userID string) (string, error)
	VerifyToken(tokenString string) (*jwt.Token, error)
	GetRefreshExpiresIn() time.Duration
}

var (
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrInvalidAppID           = errors.New("invalid app id")
	ErrUserExists             = errors.New("user already exists")
	ErrUserNotFound           = errors.New("user not found")
	ErrAppExists              = errors.New("app already exists")
	ErrInvalidUserID          = errors.New("invalid user id")
	ErrInvalidRefreshToken    = errors.New("invalid refresh token")
	ErrInvalidAccessToken     = errors.New("invalid access token")
	ErrAccessTokenGen         = errors.New("generation err access token")
	ErrRefreshTokenGen        = errors.New("generation err refresh token")
	ErrRefreshTokenStoreDB    = errors.New("store err refresh token to db")
	ErrRefreshTokenStoreRedis = errors.New("store err refresh token to redis")
	ErrOtpNotFound            = errors.New("otp not found")
)

type AuthHandlers struct {
	log             *slog.Logger
	validator       *validator.Validate
	usrSaver        UserSaver
	usrProvider     UserProvider
	tokenProvider   TokenProvider
	tokenRedisStore TokenRedisStore
	otpRedisStore   OTPRedisStore
	rabbitMQQueues  RabbitMQQueues
	passwordHasher  crypto.PasswordHasher
	jwtManager      JWTManager
}

// New returns a new instance of the Auth service.
func New(
	log *slog.Logger,
	validator *validator.Validate,
	userSaver UserSaver,
	userProvider UserProvider,
	tokenProvider TokenProvider,
	tokenRedisStore TokenRedisStore,
	otpRedisStore OTPRedisStore,
	rabbitMQQueues RabbitMQQueues,
	passwordHasher crypto.PasswordHasher,
	jwtManager JWTManager,
) *AuthHandlers {
	return &AuthHandlers{
		log:             log,
		validator:       validator,
		usrSaver:        userSaver,
		usrProvider:     userProvider,
		tokenProvider:   tokenProvider,
		tokenRedisStore: tokenRedisStore,
		otpRedisStore:   otpRedisStore,
		rabbitMQQueues:  rabbitMQQueues,
		passwordHasher:  passwordHasher,
		jwtManager:      jwtManager,
	}
}

// Login checks if user with given credentials exists in the system.
//
// If user exists, but password is incorrect, returns error.
// If user doesn't exist, returns error.
func (ah *AuthHandlers) LoginUser(
	ctx context.Context,
	email string,
	password string,
) (*models.LogInTokens, error) {
	const op = "auth.LoginUser"

	log := ah.log.With(
		slog.String("op", op),
		slog.String("username", email),
	)

	log.Info("attempting to login user")

	user, err := ah.usrProvider.FindUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", slog.String("err", err.Error()))
			return nil, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		log.Error("failed to get user", slog.String("err", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if !ah.passwordHasher.ComparePassword(user.PassHash, password) {
		log.Info("invalid credentials")
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	return ah.generateTokens(ctx, log, user.ID)
}

func (ah *AuthHandlers) LogInViaTg(ctx context.Context, login *models.LogInViaTg) error {
	const op = "auth.LogInViaTg"

	log := ah.log.With(
		slog.String("op", op),
		slog.String("login", login.Email),
	)

	// Validation
	err := ah.validator.Struct(login)
	if err != nil {
		log.Warn("invalid parameters", slog.String("err", err.Error()))
		return fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	log.Info("attempting to send otp")

	user, err := ah.usrProvider.FindUserByEmail(ctx, login.Email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			ah.log.Warn("user not found", slog.String("err", err.Error()))
			return fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}

		ah.log.Error("failed to get user", slog.String("err", err.Error()))
		return fmt.Errorf("%s: %w", op, err)
	}

	chatID, err := ah.usrProvider.GetExistChatID(ctx, user.ID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			ah.log.Warn("user not found", slog.String("err", err.Error()))
			return fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		return fmt.Errorf("%s: %w", op, err)
	}

	if chatID != "" {
		otp := &redis.CreateOTP{
			UserID:    user.ID,
			Code:      otp.RandOTP(),
			ExpiresAt: time.Now().Add(time.Minute), // TODO: transfer to config
			Used:      false,
		}

		if err = ah.otpRedisStore.SaveOTPToRedis(ctx, otp); err != nil {
			log.Error("failed to save otp to redis", slog.String("err", err.Error()))
			return fmt.Errorf("%s: %w", op, err)
		}

		chatIDInt, err := strconv.Atoi(chatID)
		if err != nil {
			ah.log.Error("err to convert chat_id to int", slog.String("err", err.Error()))
			return fmt.Errorf("%s: %w", op, err)
		}

		msgOTP := &rabbitmq.MsgOTP{
			Otp:    *otp,
			ChatID: chatIDInt,
		}

		msgBody, err := json.Marshal(msgOTP)
		if err != nil {
			ah.log.Error("err to marshal otp", slog.String("err", err.Error()))
			return fmt.Errorf("%s: %w", op, err)
		}

		if err = ah.rabbitMQQueues.Publish(ctx, exchangeOTP, otpRoutingKey, msgBody); err != nil {
			ah.log.Error("err send otp to exchange", slog.String("err", err.Error()))
			return fmt.Errorf("%s: %w", op, err)
		}
	}

	return nil
}

func (ah *AuthHandlers) CheckOTP(ctx context.Context, checkOTP *models.LoginUserOTP) (*models.LogInTokens, error) {
	const op = "auth.CheckOTP"

	log := ah.log.With(
		slog.String("op", op),
		slog.String("login", checkOTP.Email),
	)

	log.Info("attempting to login user via OTP")

	user, err := ah.usrProvider.FindUserByEmail(ctx, checkOTP.Email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", slog.String("err", err.Error()))
			return nil, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		log.Error("failed to get user", slog.String("err", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	otp, err := ah.otpRedisStore.FindOTPCode(ctx, checkOTP.Code)
	if err != nil || user.ID != otp.UserID {
		log.Info("invalid credentials")
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	if err := ah.otpRedisStore.DeleteUserOTP(ctx, checkOTP.Code); err != nil {
		log.Info("invalid credentials")
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	return ah.generateTokens(ctx, log, user.ID)
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
		Email:    user.Email,
		PassHash: passHash,
		Name:     user.Name,
		IsAdmin:  false,
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

// UpdateUserInfo updates user info
func (ah *AuthHandlers) UpdateUserInfo(ctx context.Context, userInfo *models.UpdateUserInfo) error {
	const op = "auth.UpdateUserInfo"

	log := ah.log.With(
		slog.String("op", op),
		slog.String("user_id", userInfo.ID),
	)

	// Validation
	err := ah.validator.Struct(userInfo)
	if err != nil {
		log.Warn("invalid parameters", slog.String("err", err.Error()))
		return fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	log.Info("updating user_info")

	newUserInfo := &models.DBUpdateUserInfo{
		ID:      userInfo.ID,
		Email:   userInfo.Email,
		Name:    userInfo.Name,
		TgLink:  userInfo.TgLink,
		IsAdmin: &userInfo.IsAdmin,
		Updated: time.Now(),
	}
	err = ah.usrSaver.UpdateUserInfo(ctx, newUserInfo)
	if err != nil {
		if errors.Is(err, storage.ErrInvalidCredentials) {
			ah.log.Warn("invalid credentials", slog.String("err", err.Error()))
			return fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		log.Error("failed to update user info", slog.String("err", err.Error()))
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (ah *AuthHandlers) RefreshToken(ctx context.Context, refreshToken string) (string, error) {
	const op = "auth.RefreshToken"

	// TODO: find user by refresh token
	log := ah.log.With(
		slog.String("op", op),
		// slog.String("user_id", userIDByToken),
	)

	log.Info("changing access token")

	token, err := ah.jwtManager.VerifyToken(refreshToken)
	if err != nil {
		log.Error("token verification failed: %v", slog.String("err", err.Error()))
		return "", fmt.Errorf("%s: %w", op, ErrInvalidRefreshToken)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid || claims["type"] != "refresh" {
		log.Error("invalid token claims or type")
		return "", fmt.Errorf("%s: %w", op, ErrInvalidRefreshToken)
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		log.Error("invalid userID claim")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	accessToken, err := ah.jwtManager.IssueAccessToken(userID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return accessToken, nil
}

// IsAdmin checks if user is admin.
func (ah *AuthHandlers) IsAdmin(ctx context.Context, userID string) (bool, error) {
	const op = "auth.IsAdmin"

	log := ah.log.With(
		slog.String("op", op),
		slog.String("user_id", userID),
	)

	log.Info("check user is admin")

	role, err := ah.usrProvider.GetUserRoles(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			ah.log.Warn("user not found", slog.String("err", err.Error()))
			return false, fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		return false, fmt.Errorf("%s: %w", op, err)
	}

	if !role.IsAdmin {
		log.Info("checked user is admin", slog.Bool("is_admin", false))
		return false, nil
	}

	log.Info("checked user is admin", slog.Bool("is_admin", true))

	return true, nil
}

func (ah *AuthHandlers) AuthCheck(ctx context.Context, accessToken string) (*models.AuthCheck, error) {
	const op = "auth.AuthCheck"

	// TODO: find user by access token
	log := ah.log.With(
		slog.String("op", op),
		// slog.String("user_id", userIDByToken),
	)

	log.Info("verifying access token")

	token, err := ah.jwtManager.VerifyToken(accessToken)
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

func (ah *AuthHandlers) generateTokens(
	ctx context.Context,
	log *slog.Logger,
	userID string,
) (*models.LogInTokens, error) {
	// Checks refresh-token exists
	existingRefreshToken, err := ah.tokenRedisStore.FindRefreshToken(ctx, userID)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrNoTokensFound):
			log.Info("refresh token not found", slog.String("err", err.Error()))
		case errors.Is(err, storage.ErrUserIdConversion):
			log.Warn("invalid user id", slog.String("err", err.Error()))
		default:
			log.Error("failed to get refresh token", slog.String("err", err.Error()))
		}
	}

	// Generate new access-token
	accessToken, err := ah.jwtManager.IssueAccessToken(userID)
	if err != nil {
		log.Info("failed to generate access token", slog.String("err", err.Error()))
		return nil, fmt.Errorf("%w", ErrAccessTokenGen)
	}

	// If refresh-token exists, return it
	if existingRefreshToken != nil {
		log.Info("refresh token found in redis")
		return &models.LogInTokens{
			AccessToken:  accessToken,
			RefreshToken: existingRefreshToken.Token,
		}, nil
	}

	// Generate new refresh-token
	refreshToken, err := ah.jwtManager.IssueRefreshToken(userID)
	if err != nil {
		log.Info("failed to generate refresh token", slog.String("err", err.Error()))
		return nil, fmt.Errorf("%w", ErrRefreshTokenGen)
	}

	expireRefresh := time.Now().Add(ah.jwtManager.GetRefreshExpiresIn())

	// Store refresh-token to DB
	refToken := &models.CreateRefreshToken{
		UserID:    userID,
		Token:     refreshToken,
		ExpiresAt: expireRefresh,
	}
	if err := ah.tokenProvider.SaveRefreshTokenToDB(ctx, refToken); err != nil {
		log.Error("failed to save refresh token to database", slog.String("err", err.Error()))
		return nil, fmt.Errorf("%w", ErrRefreshTokenStoreDB)
	}

	// Store refresh-token to Redis
	refTokenToRedis := &redis.CreateRefreshToken{
		UserID:    userID,
		Token:     refreshToken,
		ExpiresAt: expireRefresh,
	}
	if err := ah.tokenRedisStore.SaveRefreshTokenToRedis(ctx, refTokenToRedis); err != nil {
		log.Error("failed to save refresh token to redis", slog.String("err", err.Error()))
		return nil, fmt.Errorf("%w", ErrRefreshTokenStoreRedis)
	}

	return &models.LogInTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
