package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds runtime settings sourced from environment variables. Both the
// API server and the MCP server read from the same set so they can point at the
// same database file.
type Config struct {
	Addr           string
	DBPath         string
	MCPHTTPAddr    string
	DetectInterval time.Duration
	AuthFailLimit  int
	RateLimit      int
	RateWindow     time.Duration
}

func Load() Config {
	return Config{
		Addr:           env("SECLOG_ADDR", ":8080"),
		DBPath:         env("SECLOG_DB", "seclog.db"),
		MCPHTTPAddr:    env("SECLOG_MCP_HTTP", ""),
		DetectInterval: envDuration("SECLOG_DETECT_INTERVAL", 10*time.Second),
		AuthFailLimit:  envInt("SECLOG_AUTHFAIL_LIMIT", 5),
		RateLimit:      envInt("SECLOG_RATE_LIMIT", 100),
		RateWindow:     envDuration("SECLOG_RATE_WINDOW", time.Minute),
	}
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
