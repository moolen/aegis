package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	aegisruntime "github.com/moolen/aegis/internal/runtime"
)

var runRuntime = aegisruntime.Run

func main() {
	os.Exit(runCLI(os.Args[1:]))
}

func run() int {
	return runServe(os.Args[1:])
}

func runServe(args []string) int {
	fs := newFlagSet("aegis")
	configPath := fs.String("config", "aegis.example.yaml", "Path to the Aegis configuration file.")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := runRuntime(ctx, aegisruntime.Options{
		ConfigPath: *configPath,
		Logger:     logger,
	}); err != nil {
		return 1
	}
	return 0
}
