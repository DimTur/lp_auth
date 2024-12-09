package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/DimTur/lp_auth/internal/services/auth"
	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	exchange   = "share"
	routingKey = "notification"
)

type AuthPlanStorage interface {
	auth.UserProvider
}

type RabbitMQQueues interface {
	auth.RabbitMQQueues
}

type ConsumerGetNotifications struct {
	msgQueue       MessageQueue
	authStorage    AuthStorage
	rabbitMQQueues RabbitMQQueues
	logger         *slog.Logger
}

func NewConsumeShare(
	msgQueue MessageQueue,
	authStorage AuthStorage,
	rabbitMQQueues RabbitMQQueues,
	logger *slog.Logger,
) *ConsumerGetNotifications {
	return &ConsumerGetNotifications{
		msgQueue:       msgQueue,
		authStorage:    authStorage,
		rabbitMQQueues: rabbitMQQueues,
		logger:         logger,
	}
}

func (c *ConsumerGetNotifications) Start(ctx context.Context,
	queueName, consumer string,
	autoAck, exclusive, noLocal, noWait bool,
	args map[string]interface{},
) error {
	const op = "ConsumerGetNotifications.Start"

	log := c.logger.With(slog.String("op", op))
	log.Info("Starting to consume notification messages")

	return c.msgQueue.Consume(
		ctx,
		queueName,
		consumer,
		autoAck,
		exclusive,
		noLocal,
		noWait,
		args,
		c.handleMessage)
}

func (c *ConsumerGetNotifications) handleMessage(ctx context.Context, msg interface{}) error {
	const (
		op        = "consumer_share.handleMessage"
		batchSize = 1
	)

	log := c.logger.With(
		slog.String("op", op),
	)

	del, ok := msg.(amqp.Delivery)
	if !ok {
		c.logger.Error("failed to cast message to amqp.Delivery")
		return nil // Return nil to avoid calling Nack/Ack
	}

	// Decoding JSON message
	var message SharePlanForUsers
	if err := json.Unmarshal(del.Body, &message); err != nil {
		c.logger.Error("failed to unmarshal message to SharePlanForUsers", slog.Any("err", err))
		return err
	}

	log.Info("message", slog.Any("message", message))

	batches := splitIntoBatches(message.UserIDs, batchSize)
	log.Info("batches", slog.Any("batches", batches))
	for _, batch := range batches {
		userInfos, err := c.authStorage.GetUsersInfoBatch(ctx, batch)
		if err != nil {
			log.Error("failed to get user info", slog.String("err", err.Error()))
			log.Info(
				"failed to get user info",
				slog.Int64("splan", message.PlanID),
				slog.Any("with_users", message.UserIDs),
			)
			continue
		}
		log.Info("userInfos", slog.Any("userInfos", userInfos))

		for _, user := range userInfos {
			newMsg := struct {
				UserID    string `json:"user_id"`
				Email     string `json:"email"`
				TgLink    string `json:"tg_link"`
				ChatID    string `json:"chat_id"`
				ChannelID int64  `json:"channel_id"`
				PlanID    int64  `json:"plan_id"`
				CreatedBy string `json:"created_by"`
			}{
				UserID:    user.UserID,
				Email:     user.Email,
				TgLink:    user.TgLink,
				ChannelID: message.ChannelID,
				PlanID:    message.PlanID,
				CreatedBy: message.CreatedBy,
			}

			msgBody, err := json.Marshal(newMsg)
			if err != nil {
				log.Error("Failed to marshal message", slog.Any("err", err))
				return fmt.Errorf("%s: %w", op, err)
			}

			log.Info(
				"successfully",
				slog.Int64("splan", newMsg.PlanID),
				slog.Any("with_users", newMsg.UserID),
			)

			if err := c.rabbitMQQueues.Publish(ctx, exchange, routingKey, msgBody); err != nil {
				log.Error("err send sharing notification to exchange", slog.String("err", err.Error()))
				return fmt.Errorf("%s: %w", op, err)
			}
		}
	}

	return nil
}

func splitIntoBatches(userIDs []string, batchSize int) [][]string {
	var batches [][]string
	for i := 0; i < len(userIDs); i += batchSize {
		end := i + batchSize
		if end > len(userIDs) {
			end = len(userIDs)
		}
		batches = append(batches, userIDs[i:end])
	}
	return batches
}
