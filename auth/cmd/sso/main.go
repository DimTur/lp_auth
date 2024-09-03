package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/DimTur/learning_platform/auth/internal/app"
	"github.com/DimTur/learning_platform/auth/internal/config"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func main() {
	cfg, err := config.Parce()
	if err != nil {
		return
	}

	log := setupLogger(cfg.Env)
	log.Info("starting application", slog.Any("cfg", cfg)) // TODO: delete config

	application := app.New(log, cfg.GRPC.Port, cfg.StoragePath, cfg.TokenTTL)
	go func() {
		if err := application.GRPCSrv.Run(); err != nil {
			return
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	sign := <-stop
	log.Info("stopping application", slog.String("signal", sign.String()))

	application.GRPCSrv.Stop()
	log.Info("application stopped")
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}

	return log
}
