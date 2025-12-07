package smbfs

import (
	"errors"
	"io/fs"
	"testing"
)

func TestPathError(t *testing.T) {
	baseErr := errors.New("base error")
	pathErr := &fs.PathError{
		Op:   "open",
		Path: "/path/to/file",
		Err:  baseErr,
	}

	// Test Error() method
	expected := "open /path/to/file: base error"
	if pathErr.Error() != expected {
		t.Errorf("Error() = %q, want %q", pathErr.Error(), expected)
	}

	// Test Unwrap() method
	if unwrapped := pathErr.Unwrap(); unwrapped != baseErr {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, baseErr)
	}
}

func TestWrapPathError(t *testing.T) {
	tests := []struct {
		name     string
		op       string
		path     string
		err      error
		wantNil  bool
		wantPath string
	}{
		{
			name:    "nil error returns nil",
			op:      "open",
			path:    "/path",
			err:     nil,
			wantNil: true,
		},
		{
			name:     "wraps basic error",
			op:       "open",
			path:     "/path/to/file",
			err:      errors.New("base error"),
			wantNil:  false,
			wantPath: "/path/to/file",
		},
		{
			name: "doesn't double-wrap same path",
			op:   "read",
			path: "/path/to/file",
			err: &fs.PathError{
				Op:   "open",
				Path: "/path/to/file",
				Err:  errors.New("base error"),
			},
			wantNil:  false,
			wantPath: "/path/to/file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wrapPathError(tt.op, tt.path, tt.err)

			if tt.wantNil {
				if result != nil {
					t.Errorf("wrapPathError() = %v, want nil", result)
				}
				return
			}

			if result == nil {
				t.Fatal("wrapPathError() = nil, want error")
			}

			var pathErr *fs.PathError
			if !errors.As(result, &pathErr) {
				t.Fatalf("wrapPathError() result is not a PathError: %T", result)
			}

			if pathErr.Path != tt.wantPath {
				t.Errorf("PathError.Path = %q, want %q", pathErr.Path, tt.wantPath)
			}
		})
	}
}

func TestConvertError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected error
	}{
		{
			name:     "nil error returns nil",
			err:      nil,
			expected: nil,
		},
		{
			name:     "fs.ErrNotExist passes through",
			err:      fs.ErrNotExist,
			expected: fs.ErrNotExist,
		},
		{
			name:     "fs.ErrExist passes through",
			err:      fs.ErrExist,
			expected: fs.ErrExist,
		},
		{
			name:     "fs.ErrPermission passes through",
			err:      fs.ErrPermission,
			expected: fs.ErrPermission,
		},
		{
			name:     "fs.ErrInvalid passes through",
			err:      fs.ErrInvalid,
			expected: fs.ErrInvalid,
		},
		{
			name:     "fs.ErrClosed passes through",
			err:      fs.ErrClosed,
			expected: fs.ErrClosed,
		},
		{
			name:     "ErrConnectionClosed converts to fs.ErrClosed",
			err:      ErrConnectionClosed,
			expected: fs.ErrClosed,
		},
		{
			name:     "ErrInvalidPath converts to fs.ErrInvalid",
			err:      ErrInvalidPath,
			expected: fs.ErrInvalid,
		},
		{
			name:     "ErrAuthenticationFailed converts to fs.ErrPermission",
			err:      ErrAuthenticationFailed,
			expected: fs.ErrPermission,
		},
		{
			name:     "unknown error passes through",
			err:      errors.New("unknown error"),
			expected: nil, // Will check manually that it's the same error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertError(tt.err)

			if tt.err == nil {
				if result != nil {
					t.Errorf("convertError() = %v, want nil", result)
				}
				return
			}

			if tt.expected == nil {
				// For unknown errors, check they pass through unchanged
				if result != tt.err {
					t.Errorf("convertError() = %v, want %v (same error)", result, tt.err)
				}
				return
			}

			if !errors.Is(result, tt.expected) {
				t.Errorf("convertError() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error is not retryable",
			err:      nil,
			expected: false,
		},
		{
			name:     "ErrConnectionClosed is retryable",
			err:      ErrConnectionClosed,
			expected: true,
		},
		{
			name:     "ErrPoolExhausted is retryable",
			err:      ErrPoolExhausted,
			expected: true,
		},
		{
			name:     "ErrInvalidConfig is not retryable",
			err:      ErrInvalidConfig,
			expected: false,
		},
		{
			name:     "ErrAuthenticationFailed is not retryable",
			err:      ErrAuthenticationFailed,
			expected: false,
		},
		{
			name:     "generic error is not retryable",
			err:      errors.New("generic error"),
			expected: false,
		},
		{
			name:     "fs.ErrNotExist is not retryable",
			err:      fs.ErrNotExist,
			expected: false,
		},
		{
			name:     "wrapped ErrConnectionClosed is retryable",
			err:      wrapPathError("read", "/path", ErrConnectionClosed),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRetryable(tt.err)

			if result != tt.expected {
				t.Errorf("isRetryable(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestErrorConstants(t *testing.T) {
	// Verify all error constants are defined and unique
	errors := []error{
		ErrNotImplemented,
		ErrInvalidConfig,
		ErrConnectionClosed,
		ErrPoolExhausted,
		ErrAuthenticationFailed,
		ErrUnsupportedDialect,
		ErrInvalidPath,
		ErrNotDirectory,
		ErrIsDirectory,
	}

	// Check they're all non-nil
	for i, err := range errors {
		if err == nil {
			t.Errorf("error constant at index %d is nil", i)
		}
	}

	// Check they're all unique (by comparing error messages)
	seen := make(map[string]bool)
	for _, err := range errors {
		msg := err.Error()
		if seen[msg] {
			t.Errorf("duplicate error message: %q", msg)
		}
		seen[msg] = true
	}
}

func TestPathError_ErrorChaining(t *testing.T) {
	// Test error chain: PathError -> wrapped error -> base error
	baseErr := errors.New("connection refused")
	wrappedErr := wrapPathError("connect", "/server/share", baseErr)

	// Should be able to unwrap to base error
	if !errors.Is(wrappedErr, baseErr) {
		t.Error("errors.Is() failed to find base error in chain")
	}

	// PathError itself should be in the chain
	var pathErr *fs.PathError
	if !errors.As(wrappedErr, &pathErr) {
		t.Error("errors.As() failed to find PathError in chain")
	}

	if pathErr.Op != "connect" {
		t.Errorf("PathError.Op = %q, want %q", pathErr.Op, "connect")
	}
	if pathErr.Path != "/server/share" {
		t.Errorf("PathError.Path = %q, want %q", pathErr.Path, "/server/share")
	}
}
