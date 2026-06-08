package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"seclog/internal/config"
	mcptools "seclog/internal/mcp"
	"seclog/internal/store"
)

func main() {
	httpAddr := flag.String("http", "", "serve streamable HTTP on this address (e.g. :8081); default is stdio")
	flag.Parse()

	// Logs go to stderr because stdout is the stdio transport channel.
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.Load()

	addr := *httpAddr
	if addr == "" {
		addr = cfg.MCPHTTPAddr
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	srv := mcptools.New(st)

	if addr != "" {
		handler := mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server {
			return srv
		}, nil)
		log.Info("mcp streamable http listening", "addr", addr, "db", cfg.DBPath)
		if err := http.ListenAndServe(addr, handler); err != nil {
			log.Error("listen", "err", err)
			os.Exit(1)
		}
		return
	}

	if err := srv.Run(context.Background(), &mcpsdk.StdioTransport{}); err != nil {
		log.Error("mcp stdio run", "err", err)
		os.Exit(1)
	}
}
