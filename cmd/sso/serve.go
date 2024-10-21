package sso

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/DimTur/lp_auth/internal/app"
	"github.com/DimTur/lp_auth/internal/config"
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

			cfg, err := config.Parse(configPath)
			if err != nil {
				return err
			}

			fmt.Println("Username:", cfg.Storage.UserName)
			fmt.Println("Password:", cfg.Storage.Password)
			fmt.Println("DB Name:", cfg.Storage.DbName)

			uri := fmt.Sprintf(
				"mongodb://%s:%s@localhost:27017/%s?authSource=admin",
				cfg.Storage.UserName,
				cfg.Storage.Password,
				cfg.Storage.DbName,
			)

			fmt.Println(uri)

			storage, err := mongodb.NewMongoClient(ctx, uri, cfg.Storage.DbName)
			if err != nil {
				return err
			}
			defer func() {
				if err := storage.Close(ctx); err != nil {
					log.Error("failed to close db", slog.Any("err", err))
				}
			}()

			redisOpts := &authredis.RedisOpts{
				Host:     cfg.Redis.Host,
				Port:     cfg.Redis.Port,
				DB:       cfg.Redis.Db,
				Password: cfg.Redis.Password,
			}
			authRedis, err := authredis.NewRedisClient(*redisOpts)

			validate := validator.New()

			application, err := app.NewApp(
				storage,
				authRedis,
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

			grpcCloser, err := application.GRPCSrv.Run()
			if err != nil {
				return err
			}

			log.Info("server listening:", slog.Any("port", cfg.GRPCServer.Address))
			<-ctx.Done()

			grpcCloser()

			return nil
		},
	}

	c.Flags().StringVar(&configPath, "config", "", "path to config")
	return c
}
