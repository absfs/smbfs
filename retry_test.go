package smbfs

import (
	"context"
	"errors"
	"testing"
	"time"
)

// mockNetError implements netError interface for testing.
type mockNetError struct {
	error
	temporary bool
	timeout   bool
}

func (e *mockNetError) Temporary() bool { return e.temporary }
func (e *mockNetError) Timeout() bool   { return e.timeout }

func TestWithRetry_Success(t *testing.T) {
	config := &Config{
		Server:   "test",
		Share:    "test",
		Username: "test",
		Password: "test",
	}
	config.setDefaults()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fs := &FileSystem{
		config: config,
		ctx:    ctx,
	}

	callCount := 0
	err := fs.withRetry(ctx, func() error {
		callCount++
		return nil
	})

	if err != nil {
		t.Errorf("withRetry() error = %v, want nil", err)
	}

	if callCount != 1 {
		t.Errorf("operation called %d times, want 1", callCount)
	}
}

func TestWithRetry_SuccessAfterRetries(t *testing.T) {
	config := &Config{
		Server:   "test",
		Share:    "test",
		Username: "test",
		Password: "test",
		RetryPolicy: &RetryPolicy{
			MaxAttempts:  3,
			InitialDelay: 10 * time.Millisecond,
			MaxDelay:     50 * time.Millisecond,
			Multiplier:   2.0,
		},
	}
	config.setDefaults()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fs := &FileSystem{
		config: config,
		ctx:    ctx,
	}

	callCount := 0
	err := fs.withRetry(ctx, func() error {
		callCount++
		if callCount < 3 {
			// Return retryable error for first 2 attempts
			return &mockNetError{error: errors.New("temp error"), temporary: true}
		}
		return nil
	})

	if err != nil {
		t.Errorf("withRetry() error = %v, want nil", err)
	}

	if callCount != 3 {
		t.Errorf("operation called %d times, want 3", callCount)
	}
}

func TestWithRetry_NonRetryableError(t *testing.T) {
	config := &Config{
		Server:   "test",
		Share:    "test",
		Username: "test",
		Password: "test",
		RetryPolicy: &RetryPolicy{
			MaxAttempts:  3,
			InitialDelay: 10 * time.Millisecond,
			MaxDelay:     50 * time.Millisecond,
			Multiplier:   2.0,
		},
	}
	config.setDefaults()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fs := &FileSystem{
		config: config,
		ctx:    ctx,
	}

	nonRetryableErr := errors.New("not retryable")
	callCount := 0

	err := fs.withRetry(ctx, func() error {
		callCount++
		return nonRetryableErr
	})

	if err != nonRetryableErr {
		t.Errorf("withRetry() error = %v, want %v", err, nonRetryableErr)
	}

	if callCount != 1 {
		t.Errorf("operation called %d times, want 1 (should not retry non-retryable errors)", callCount)
	}
}

func TestWithRetry_MaxAttemptsExceeded(t *testing.T) {
	config := &Config{
		Server:   "test",
		Share:    "test",
		Username: "test",
		Password: "test",
		RetryPolicy: &RetryPolicy{
			MaxAttempts:  3,
			InitialDelay: 10 * time.Millisecond,
			MaxDelay:     50 * time.Millisecond,
			Multiplier:   2.0,
		},
	}
	config.setDefaults()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fs := &FileSystem{
		config: config,
		ctx:    ctx,
	}

	retryableErr := &mockNetError{error: errors.New("always fails"), temporary: true}
	callCount := 0

	err := fs.withRetry(ctx, func() error {
		callCount++
		return retryableErr
	})

	if err == nil {
		t.Errorf("withRetry() error = nil, want error")
	}

	if callCount != 3 {
		t.Errorf("operation called %d times, want 3", callCount)
	}
}

func TestWithRetry_ContextCancellation(t *testing.T) {
	config := &Config{
		Server:   "test",
		Share:    "test",
		Username: "test",
		Password: "test",
		RetryPolicy: &RetryPolicy{
			MaxAttempts:  5,
			InitialDelay: 100 * time.Millisecond,
			MaxDelay:     500 * time.Millisecond,
			Multiplier:   2.0,
		},
	}
	config.setDefaults()

	ctx, cancel := context.WithCancel(context.Background())

	fs := &FileSystem{
		config: config,
		ctx:    ctx,
	}

	callCount := 0
	errChan := make(chan error, 1)

	go func() {
		err := fs.withRetry(ctx, func() error {
			callCount++
			if callCount == 2 {
				// Cancel context on second attempt
				cancel()
			}
			return &mockNetError{error: errors.New("temp error"), temporary: true}
		})
		errChan <- err
	}()

	err := <-errChan

	if err != context.Canceled {
		t.Errorf("withRetry() error = %v, want context.Canceled", err)
	}

	if callCount < 2 {
		t.Errorf("operation called %d times, want at least 2", callCount)
	}
}

func TestWithRetry_ExponentialBackoff(t *testing.T) {
	config := &Config{
		Server:   "test",
		Share:    "test",
		Username: "test",
		Password: "test",
		RetryPolicy: &RetryPolicy{
			MaxAttempts:  4,
			InitialDelay: 50 * time.Millisecond,
			MaxDelay:     300 * time.Millisecond,
			Multiplier:   2.0,
		},
	}
	config.setDefaults()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fs := &FileSystem{
		config: config,
		ctx:    ctx,
	}

	attempts := make([]time.Time, 0)

	err := fs.withRetry(ctx, func() error {
		attempts = append(attempts, time.Now())
		return &mockNetError{error: errors.New("temp error"), temporary: true}
	})

	if err == nil {
		t.Errorf("withRetry() error = nil, want error")
	}

	if len(attempts) != 4 {
		t.Errorf("got %d attempts, want 4", len(attempts))
		return
	}

	// Check that delays roughly follow exponential backoff
	// Attempt 1 -> 2: ~50ms
	// Attempt 2 -> 3: ~100ms
	// Attempt 3 -> 4: ~200ms
	delay1 := attempts[1].Sub(attempts[0])
	delay2 := attempts[2].Sub(attempts[1])
	delay3 := attempts[3].Sub(attempts[2])

	// Allow some variance for timing
	if delay1 < 40*time.Millisecond || delay1 > 100*time.Millisecond {
		t.Errorf("First delay = %v, want ~50ms", delay1)
	}
	if delay2 < 80*time.Millisecond || delay2 > 150*time.Millisecond {
		t.Errorf("Second delay = %v, want ~100ms", delay2)
	}
	if delay3 < 150*time.Millisecond || delay3 > 250*time.Millisecond {
		t.Errorf("Third delay = %v, want ~200ms", delay3)
	}
}
