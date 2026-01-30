package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	"github.com/shuklarituparn/Gopherpass/internal/server/auth"
	"github.com/shuklarituparn/Gopherpass/internal/server/config"
	"github.com/shuklarituparn/Gopherpass/internal/server/handlers"
	"github.com/shuklarituparn/Gopherpass/internal/server/service"
	"github.com/shuklarituparn/Gopherpass/internal/server/storage"
	pb "github.com/shuklarituparn/Gopherpass/pkg/proto"
)

var (
	buildVersion = "dev"
	buildDate    = "unknown"
	buildCommit  = "unknown"
)

func main() {
	log.Printf("GophKeeper Server v%s (built %s, commit %s)", buildVersion, buildDate, buildCommit)

	cfg := config.Load()

	if errs := cfg.Validate(); len(errs) > 0 {
		for _, err := range errs {
			log.Printf("Config error: %v", err)
		}
		os.Exit(1)
	}

	store, err := storage.NewPostgresStorage(cfg.DatabaseDSN)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	log.Println("Connected to database")

	svc := service.NewGophKeeperService(store)

	tokenManager := auth.NewTokenManager(cfg.JWTSecret, cfg.JWTExpiration)

	handler := handlers.NewGRPCHandler(svc, tokenManager)

	publicMethods := map[string]bool{
		"/gophkeeper.GophKeeper/Register": true,
		"/gophkeeper.GophKeeper/Login":    true,
	}

	var opts []grpc.ServerOption
	opts = append(opts,
		grpc.UnaryInterceptor(tokenManager.AuthInterceptor(publicMethods)),
		grpc.StreamInterceptor(tokenManager.StreamAuthInterceptor(publicMethods)),
	)

	if cfg.EnableTLS {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			log.Fatalf("Failed to load TLS certificates: %v", err)
		}
		opts = append(opts, grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
		log.Println("TLS enabled")
	}

	grpcServer := grpc.NewServer(opts...)
	pb.RegisterGophKeeperServer(grpcServer, handler)

	if cfg.Environment != "production" {
		reflection.Register(grpcServer)
		log.Println("gRPC reflection enabled")
	}

	listener, err := net.Listen("tcp", cfg.GRPCAddress)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", cfg.GRPCAddress, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()
		grpcServer.GracefulStop()
	}()

	log.Printf("Starting gRPC server on %s", cfg.GRPCAddress)
	if err := grpcServer.Serve(listener); err != nil {
		select {
		case <-ctx.Done():
			log.Println("Server stopped gracefully")
		default:
			log.Fatalf("Failed to serve: %v", err)
		}
	}
}

func printUsage() {
	fmt.Printf(`GophKeeper Server

Usage: gophkeeper-server [options]

Environment variables:
  GRPC_ADDRESS    gRPC server address (default: :3200)
  HTTP_ADDRESS    HTTP server address (default: :8080)
  DATABASE_DSN    PostgreSQL connection string
  JWT_SECRET      Secret key for JWT tokens
  JWT_EXPIRATION  Token expiration duration (default: 24h)
  ENABLE_TLS      Enable TLS (true/false)
  TLS_CERT        Path to TLS certificate
  TLS_KEY         Path to TLS private key
  LOG_LEVEL       Logging level (debug, info, warn, error)
  ENVIRONMENT     Environment (development, production)

Version: %s
Build date: %s
Commit: %s
`, buildVersion, buildDate, buildCommit)
}
