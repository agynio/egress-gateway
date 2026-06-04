package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/agynio/egress-gateway/internal/config"
	"github.com/agynio/egress-gateway/internal/server"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if err := server.New(cfg).Run(ctx); err != nil {
		log.Fatalf("run server: %v", err)
	}
}
