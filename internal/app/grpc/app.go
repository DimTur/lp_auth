package grpcapp

import (
	"log/slog"
	"net"
	"runtime/debug"
	"time"

	authgrpc "github.com/DimTur/lp_auth/internal/grpc/auth"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

const (
	// GRPCDefaultGracefulStopTimeout - period to wait result of grpc.GracefulStop
	// after call grpc.Stop
	GRPCDefaultGracefulStopTimeout = 5 * time.Second
)

// GRPC - structure describes gRPC props
type Server struct {
	gRPCAddr            string
	gRPCSrv             *grpc.Server
	listener            net.Listener
	gracefulStopTimeout time.Duration

	logger *slog.Logger
}

func NewGRPCServer(
	gRPCAddr string,
	authHandlers authgrpc.AuthHandlers,
	logger *slog.Logger,
) (*Server, error) {
	const op = "grpc-server"

	logger = logger.With(
		slog.String("op", op),
		slog.String("addr", gRPCAddr),
	)

	netListener, err := net.Listen("tcp", gRPCAddr)
	if err != nil {
		return nil, err
	}

	grpcPanicRecoveryHandler := func(p any) (err error) {
		logger.Error("recovered from panic", slog.Any("stack", string(debug.Stack())))
		return status.Errorf(codes.Internal, "%s", p)
	}

	gRPCSrv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			recovery.UnaryServerInterceptor(recovery.WithRecoveryHandler(grpcPanicRecoveryHandler)),
		),
		grpc.ChainStreamInterceptor(
			recovery.StreamServerInterceptor(recovery.WithRecoveryHandler(grpcPanicRecoveryHandler)),
		),
	)
	authgrpc.RegisterAuthServiceServer(gRPCSrv, authHandlers)

	// register health check service
	healthService := NewHealthChecker(logger)
	grpc_health_v1.RegisterHealthServer(gRPCSrv, healthService)

	// Register reflection service on gRPC server. can be a flag
	reflection.Register(gRPCSrv)

	server := &Server{
		gRPCAddr:            gRPCAddr,
		listener:            netListener,
		gRPCSrv:             gRPCSrv,
		gracefulStopTimeout: GRPCDefaultGracefulStopTimeout,
		logger:              logger,
	}

	return server, nil
}

func (s *Server) Run() (func() error, error) {
	const op = "grpcapp.Run"
	s.logger.With(slog.String("op", op)).Info("starting", slog.String("grpcAddr", s.gRPCAddr))

	go func() {
		err := s.gRPCSrv.Serve(s.listener)
		if err == grpc.ErrServerStopped {
			s.logger.Error("grpc server", slog.Any("err", err))
		}
	}()

	s.logger.Info("grpc server is running", slog.String("addr", s.gRPCAddr))
	return s.close, nil
}

// stop - gracefully stop server & listeners
func (s *Server) close() error {
	const op = "grpcapp.stop"
	s.logger.With(slog.String("op", op)).Info("stopping gRPC server", slog.String("port", s.gRPCAddr))

	stopped := make(chan struct{})
	go func() {
		s.gRPCSrv.GracefulStop()
		close(stopped)
	}()

	t := time.NewTimer(s.gracefulStopTimeout)
	defer t.Stop()

	select {
	case <-t.C:
		s.logger.With(slog.String("op", op)).Info("ungracefully stopping....", slog.String("grpcAddr", s.gRPCAddr))
		s.gRPCSrv.Stop()
	case <-stopped:
		t.Stop()
	}
	s.logger.With(slog.String("op", op)).Info("stopped", slog.String("grpcAddr", s.gRPCAddr))
	return nil
}
