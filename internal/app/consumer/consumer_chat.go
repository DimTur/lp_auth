package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/DimTur/lp_auth/internal/domain/models"
	"github.com/DimTur/lp_auth/internal/services/auth"
	"github.com/DimTur/lp_auth/internal/services/storage"
	amqp "github.com/rabbitmq/amqp091-go"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
)

type MessageQueue interface {
	Consume(
		ctx context.Context,
		queueName, consumer string,
		autoAck, exclusive, noLocal, noWait bool,
		args map[string]interface{},
		handle func(ctx context.Context, msg interface{}) error,
	) error
}

type AuthStorage interface {
	auth.UserSaver
	auth.UserProvider
}

type ConsumeUserChatID struct {
	msgQueue    MessageQueue
	authStorage AuthStorage
	logger      *slog.Logger
}

func NewConsumeChat(
	msgQueue MessageQueue,
	authStorage AuthStorage,
	logger *slog.Logger,
) *ConsumeUserChatID {
	return &ConsumeUserChatID{
		msgQueue:    msgQueue,
		authStorage: authStorage,
		logger:      logger,
	}
}

func (c *ConsumeUserChatID) Start(
	ctx context.Context,
	queueName, consumer string,
	autoAck, exclusive, noLocal, noWait bool,
	args map[string]interface{},
) error {
	const op = "NewConsumeChat.Start"

	log := c.logger.With(slog.String("op", op))
	log.Info("Starting to consume OTP messages")

	return c.msgQueue.Consume(
		ctx,
		queueName,
		consumer,
		autoAck,
		exclusive,
		noLocal,
		noWait,
		args,
		c.handleMessage,
	)
}

func (c *ConsumeUserChatID) handleMessage(ctx context.Context, msg interface{}) error {
	const op = "consumer.handleMessage"

	log := c.logger.With(
		slog.String("op", op),
	)

	del, ok := msg.(amqp.Delivery)
	if !ok {
		c.logger.Error("failed to cast message to amqp.Delivery")
		return nil // Return nil to avoid calling Nack/Ack
	}

	var message models.UserTg
	// Decoding JSON message
	if err := json.Unmarshal(del.Body, &message); err != nil {
		c.logger.Error("failed to unmarshal message to UserTg", slog.Any("err", err))
		return err
	}

	user, err := c.authStorage.FindUserByTgLink(ctx, message.TgLink)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", slog.String("err", err.Error()))
			return fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		log.Error("failed to update user info", slog.String("err", err.Error()))
		return fmt.Errorf("%s: %w", op, err)
	}

	chatID := &models.DBUpdateUserInfo{
		ID:      user.ID,
		ChatID:  message.ChatID,
		Updated: time.Now(),
	}
	if err = c.authStorage.UpdateUserInfo(ctx, chatID); err != nil {
		if errors.Is(err, storage.ErrInvalidCredentials) {
			log.Warn("invalid credentials", slog.String("err", err.Error()))
			return fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		log.Error("failed to save user chat id", slog.String("err", err.Error()))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("handling message")

	return nil
}
