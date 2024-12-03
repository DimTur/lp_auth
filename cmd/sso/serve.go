package sso

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/DimTur/lp_auth/internal/app"
	"github.com/DimTur/lp_auth/internal/app/consumer"
	"github.com/DimTur/lp_auth/internal/config"
	"github.com/DimTur/lp_auth/internal/services/rabbitmq"
	"github.com/DimTur/lp_auth/internal/services/storage/mongodb"
	authredis "github.com/DimTur/lp_auth/internal/services/storage/redis"
	"github.com/go-playground/validator/v10"
	"github.com/spf13/cobra"
)

func NewServeCmd() *cobra.Command {
	var configPath string

	c := &cobra.Command{
		Use:     "serve",
		Aliases: []string{"s"},
		Short:   "Start API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
			defer cancel()
			var wg sync.WaitGroup

			cfg, err := config.Parse(configPath)
			if err != nil {
				return err
			}

			uri := fmt.Sprintf(
				"mongodb://%s:%s@localhost:27017/%s?authSource=admin",
				cfg.Storage.UserName,
				cfg.Storage.Password,
				cfg.Storage.DbName,
			)

			storage, err := mongodb.NewMongoClient(ctx, uri, cfg.Storage.DbName)
			if err != nil {
				return err
			}
			defer func() {
				if err := storage.Close(ctx); err != nil {
					log.Error("failed to close db", slog.Any("err", err))
				}
			}()

			redisTokenOpts := &authredis.RedisOpts{
				Host:     cfg.Redis.Host,
				Port:     cfg.Redis.Port,
				DB:       cfg.Redis.TokenDB,
				Password: cfg.Redis.Password,
			}
			tokenRedis, err := authredis.NewRedisClient(*redisTokenOpts)
			if err != nil {
				log.Error("failed to close redis", slog.Any("err", err))
			}

			redisOTPOpts := &authredis.RedisOpts{
				Host:     cfg.Redis.Host,
				Port:     cfg.Redis.Port,
				DB:       cfg.Redis.OtpDB,
				Password: cfg.Redis.Password,
			}
			otpRedis, err := authredis.NewRedisClient(*redisOTPOpts)
			if err != nil {
				log.Error("failed to close redis", slog.Any("err", err))
			}

			// Init RabbitMQ
			rmq, err := initRabbitMQ(cfg)
			if err != nil {
				log.Error("failed init rabbit mq", slog.Any("err", err))
			}

			// Declare OTP exchange
			if err := declareOTPExchange(rmq, cfg); err != nil {
				log.Error("failed to declare OTP exchange", slog.Any("err", err))
			}

			// Declare and bind OTP Queue
			if err := declareQueueAndBind(
				rmq,
				cfg.RabbitMQ.OTP.OTPQueue,
				cfg.RabbitMQ.OTP.OTPExchange.Name,
				cfg.RabbitMQ.OTP.OTPRoutingKey,
			); err != nil {
				log.Error("failed to declare and bind OTP Queue", slog.Any("err", err))
			}

			// Declare and bind Notification Queue
			if err := declareQueueAndBind(
				rmq,
				cfg.RabbitMQ.Notification.NotificationQueue,
				cfg.RabbitMQ.Notification.NotificationExchange.Name,
				cfg.RabbitMQ.Notification.NotificationRoutingKey,
			); err != nil {
				log.Error("failed to declare and bind Notification Queue", slog.Any("err", err))
			}

			// Declare and bind SPFU Queue
			if err := declareQueueAndBind(
				rmq,
				cfg.RabbitMQ.Spfu.SpfuQueue,
				cfg.RabbitMQ.Spfu.SpfuExchange.Name,
				cfg.RabbitMQ.Spfu.SpfuRoutingKey,
			); err != nil {
				log.Error("failed to declare and spfu Notification Queue", slog.Any("err", err))
			}

			validate := validator.New()

			application, err := app.NewApp(
				storage,
				storage,
				tokenRedis,
				otpRedis,
				rmq,
				cfg.JWT.Issuer,
				cfg.JWT.AccessExpiresIn,
				cfg.JWT.RefreshExpiresIn,
				cfg.JWT.PublicKey,
				cfg.JWT.PrivateKey,
				cfg.GRPCServer.Address,
				log,
				validate,
			)
			if err != nil {
				return err
			}

			startConsumers(ctx, cfg, rmq, storage, log, &wg)

			grpcCloser, err := application.GRPCSrv.Run()
			if err != nil {
				return err
			}

			log.Info("server listening:", slog.Any("port", cfg.GRPCServer.Address))
			<-ctx.Done()
			wg.Wait()

			rmq.Close()
			grpcCloser()

			return nil
		},
	}

	c.Flags().StringVar(&configPath, "config", "", "path to config")
	return c
}

func initRabbitMQ(cfg *config.Config) (*rabbitmq.RMQClient, error) {
	rmqUrl := fmt.Sprintf(
		"amqp://%s:%s@%s:%d/",
		cfg.RabbitMQ.UserName,
		cfg.RabbitMQ.Password,
		cfg.RabbitMQ.Host,
		cfg.RabbitMQ.Port,
	)
	return rabbitmq.NewClient(rmqUrl)
}

func startConsumers(
	ctx context.Context,
	cfg *config.Config,
	rmq *rabbitmq.RMQClient,
	authStorage app.AuthStorage,
	log *slog.Logger,
	wg *sync.WaitGroup,
) {
	chatConsumer := consumer.NewConsumeChat(rmq, authStorage, log)
	shareConsumer := consumer.NewConsumeShare(rmq, authStorage, rmq, log)

	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := chatConsumer.Start(
			ctx,
			cfg.RabbitMQ.ChatID.ChatConsumer.Queue,
			cfg.RabbitMQ.ChatID.ChatConsumer.Consumer,
			cfg.RabbitMQ.ChatID.ChatConsumer.AutoAck,
			cfg.RabbitMQ.ChatID.ChatConsumer.Exclusive,
			cfg.RabbitMQ.ChatID.ChatConsumer.NoLocal,
			cfg.RabbitMQ.ChatID.ChatConsumer.NoWait,
			cfg.RabbitMQ.ChatID.ChatConsumer.ConsumerArgs.ToMap(),
		); err != nil {
			log.Error("failed to start chat consumer", slog.Any("err", err))
		}
	}()

	go func() {
		defer wg.Done()
		if err := shareConsumer.Start(
			ctx,
			cfg.RabbitMQ.Notification.NotificationConsumer.Queue,
			cfg.RabbitMQ.Notification.NotificationConsumer.Consumer,
			cfg.RabbitMQ.Notification.NotificationConsumer.AutoAck,
			cfg.RabbitMQ.Notification.NotificationConsumer.Exclusive,
			cfg.RabbitMQ.Notification.NotificationConsumer.NoLocal,
			cfg.RabbitMQ.Notification.NotificationConsumer.NoWait,
			cfg.RabbitMQ.Notification.NotificationConsumer.ConsumerArgs.ToMap(),
		); err != nil {
			log.Error("failed to start share plans consumer", slog.Any("err", err))
		}
	}()
}

func declareQueueAndBind(rmq *rabbitmq.RMQClient, queueConfig config.QueueConfig, exchangeName, routingKey string) error {
	// Announcement of the queue
	if _, err := rmq.DeclareQueue(
		queueConfig.Name,
		queueConfig.Durable,
		queueConfig.AutoDeleted,
		queueConfig.Exclusive,
		queueConfig.NoWait,
		queueConfig.Args.ToMap(),
	); err != nil {
		return fmt.Errorf("failed to declare queue %s: %w", queueConfig.Name, err)
	}

	// Binding a queue to an exchange
	if err := rmq.BindQueueToExchange(
		queueConfig.Name,
		exchangeName,
		routingKey,
	); err != nil {
		return fmt.Errorf("failed to bind queue %s to exchange %s: %w", queueConfig.Name, exchangeName, err)
	}

	return nil
}

func declareOTPExchange(rmq *rabbitmq.RMQClient, cfg *config.Config) error {
	return rmq.DeclareExchange(
		cfg.RabbitMQ.OTP.OTPExchange.Name,
		cfg.RabbitMQ.OTP.OTPExchange.Kind,
		cfg.RabbitMQ.OTP.OTPExchange.Durable,
		cfg.RabbitMQ.OTP.OTPExchange.AutoDeleted,
		cfg.RabbitMQ.OTP.OTPExchange.Internal,
		cfg.RabbitMQ.OTP.OTPExchange.NoWait,
		cfg.RabbitMQ.OTP.OTPExchange.Args.ToMap(),
	)
}
