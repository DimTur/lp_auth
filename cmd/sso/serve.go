package sso

import (
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
			rmqUrl := fmt.Sprintf(
				"amqp://%s:%s@%s:%d/",
				cfg.RabbitMQ.UserName,
				cfg.RabbitMQ.Password,
				cfg.RabbitMQ.Host,
				cfg.RabbitMQ.Port,
			)
			rmq, err := rabbitmq.NewClient(rmqUrl)
			if err != nil {
				log.Error("failed init rabbit mq", slog.Any("err", err))
			}

			// Declare OTP exchange
			if err := rmq.DeclareExchange(
				cfg.RabbitMQ.OTPExchange.Name,
				cfg.RabbitMQ.OTPExchange.Kind,
				cfg.RabbitMQ.OTPExchange.Durable,
				cfg.RabbitMQ.OTPExchange.AutoDeleted,
				cfg.RabbitMQ.OTPExchange.Internal,
				cfg.RabbitMQ.OTPExchange.NoWait,
				cfg.RabbitMQ.OTPExchange.Args.ToMap(),
			); err != nil {
				log.Error("failed to declare OTP exchange", slog.Any("err", err))
			}

			// Declare OTP Queue
			if _, err := rmq.DeclareQueue(
				cfg.RabbitMQ.OTPQueue.Name,
				cfg.RabbitMQ.OTPQueue.Durable,
				cfg.RabbitMQ.OTPQueue.AutoDeleted,
				cfg.RabbitMQ.OTPQueue.Exclusive,
				cfg.RabbitMQ.OTPQueue.NoWait,
				cfg.RabbitMQ.OTPQueue.Args.ToMap(),
			); err != nil {
				log.Error("failed to declare OTP queue", slog.Any("err", err))
			}

			// Bind OTP queue to OTP exchange
			if err := rmq.BindQueueToExchange(
				cfg.RabbitMQ.OTPQueue.Name,
				cfg.RabbitMQ.OTPExchange.Name,
				cfg.RabbitMQ.OTPRoutingKey,
			); err != nil {
				log.Error("failed to bind OTP queue", slog.Any("err", err))
			}

			validate := validator.New()

			application, err := app.NewApp(
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

			consumer := consumer.NewConsumeOTP(rmq, storage, log)
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := consumer.Start(ctx, cfg.RabbitMQ.ChatIDQueue.Name); err != nil {
					log.Error("failed to start chat_id consumer", slog.Any("err", err))
				}
			}()

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
