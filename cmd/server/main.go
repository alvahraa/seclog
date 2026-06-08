package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"seclog/internal/api"
	"seclog/internal/config"
	"seclog/internal/detect"
	"seclog/internal/store"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := config.Load()

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dcfg := detect.DefaultConfig()
	dcfg.AuthFailLimit = cfg.AuthFailLimit
	dcfg.RateLimit = cfg.RateLimit
	dcfg.RateWindow = cfg.RateWindow
	engine := detect.NewEngine(st, dcfg, cfg.DetectInterval, log)
	go engine.Run(ctx)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           api.New(st).Router(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	go func() {
		log.Info("api listening", "addr", cfg.Addr, "db", cfg.DBPath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown", "err", err)
	}
}
