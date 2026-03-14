package smbfs

import (
	"context"
	"fmt"
	"log/slog"
	"os"
)

// SlogLogger wraps slog.Logger to implement the ServerLogger interface
// providing structured logging with levels, attributes, and output flexibility.
type SlogLogger struct {
	logger *slog.Logger
	debug  bool
}

// SlogLoggerConfig configures the structured logger
type SlogLoggerConfig struct {
	// Level sets the minimum log level (default: Info)
	Level slog.Level

	// Format selects output format: "text" or "json" (default: "text")
	Format string

	// Output is the output destination (default: os.Stderr)
	Output *os.File

	// AddSource adds source file/line to log entries
	AddSource bool
}

// NewSlogLogger creates a structured logger using log/slog
func NewSlogLogger(config SlogLoggerConfig) *SlogLogger {
	output := config.Output
	if output == nil {
		output = os.Stderr
	}

	opts := &slog.HandlerOptions{
		Level:     config.Level,
		AddSource: config.AddSource,
	}

	var handler slog.Handler
	switch config.Format {
	case "json":
		handler = slog.NewJSONHandler(output, opts)
	default:
		handler = slog.NewTextHandler(output, opts)
	}

	return &SlogLogger{
		logger: slog.New(handler),
		debug:  config.Level <= slog.LevelDebug,
	}
}

// NewSlogLoggerFromLogger creates a SlogLogger wrapping an existing slog.Logger
func NewSlogLoggerFromLogger(logger *slog.Logger) *SlogLogger {
	return &SlogLogger{
		logger: logger,
		debug:  true,
	}
}

func (l *SlogLogger) Debug(msg string, args ...interface{}) {
	if l.debug {
		l.logger.LogAttrs(context.Background(), slog.LevelDebug, fmt.Sprintf(msg, args...))
	}
}

func (l *SlogLogger) Info(msg string, args ...interface{}) {
	l.logger.LogAttrs(context.Background(), slog.LevelInfo, fmt.Sprintf(msg, args...))
}

func (l *SlogLogger) Warn(msg string, args ...interface{}) {
	l.logger.LogAttrs(context.Background(), slog.LevelWarn, fmt.Sprintf(msg, args...))
}

func (l *SlogLogger) Error(msg string, args ...interface{}) {
	l.logger.LogAttrs(context.Background(), slog.LevelError, fmt.Sprintf(msg, args...))
}

// With returns a new SlogLogger with additional context attributes
func (l *SlogLogger) With(key string, value interface{}) *SlogLogger {
	return &SlogLogger{
		logger: l.logger.With(slog.Any(key, value)),
		debug:  l.debug,
	}
}

// Logger returns the underlying slog.Logger for advanced usage
func (l *SlogLogger) Logger() *slog.Logger {
	return l.logger
}
