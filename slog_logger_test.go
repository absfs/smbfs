package smbfs

import (
	"log/slog"
	"os"
	"testing"
)

func TestSlogLogger_Implements_ServerLogger(t *testing.T) {
	logger := NewSlogLogger(SlogLoggerConfig{
		Level:  slog.LevelDebug,
		Format: "text",
		Output: os.Stderr,
	})

	// Verify it implements ServerLogger interface
	var _ ServerLogger = logger

	// Should not panic
	logger.Debug("debug message %d", 1)
	logger.Info("info message %s", "test")
	logger.Warn("warn message")
	logger.Error("error message")
}

func TestSlogLogger_JSONFormat(t *testing.T) {
	logger := NewSlogLogger(SlogLoggerConfig{
		Level:  slog.LevelInfo,
		Format: "json",
		Output: os.Stderr,
	})

	// Should not panic with JSON format
	logger.Info("test json output")
}

func TestSlogLogger_With(t *testing.T) {
	logger := NewSlogLogger(SlogLoggerConfig{
		Level:  slog.LevelDebug,
		Format: "text",
		Output: os.Stderr,
	})

	// Create logger with additional context
	contextLogger := logger.With("component", "test")
	if contextLogger == nil {
		t.Fatal("expected non-nil logger from With")
	}

	// Should not panic
	contextLogger.Info("test with context")
}

func TestSlogLogger_FromExisting(t *testing.T) {
	existing := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logger := NewSlogLoggerFromLogger(existing)

	if logger.Logger() != existing {
		t.Error("expected same underlying logger")
	}

	// Should not panic
	logger.Debug("test from existing logger")
}

func TestNewSlogLogger_DefaultOutput(t *testing.T) {
	// nil Output should default to stderr
	logger := NewSlogLogger(SlogLoggerConfig{
		Level: slog.LevelInfo,
	})

	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
}
