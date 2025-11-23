package smbfs

import (
	"testing"
)

func TestPathNormalizer_normalize(t *testing.T) {
	tests := []struct {
		name          string
		caseSensitive bool
		path          string
		expected      string
	}{
		{
			name:          "simple path",
			caseSensitive: false,
			path:          "/path/to/file",
			expected:      "/path/to/file",
		},
		{
			name:          "windows-style path",
			caseSensitive: false,
			path:          "\\path\\to\\file",
			expected:      "/path/to/file",
		},
		{
			name:          "mixed separators",
			caseSensitive: false,
			path:          "/path\\to/file",
			expected:      "/path/to/file",
		},
		{
			name:          "path with ..",
			caseSensitive: false,
			path:          "/path/to/../file",
			expected:      "/path/file",
		},
		{
			name:          "path with .",
			caseSensitive: false,
			path:          "/path/./to/file",
			expected:      "/path/to/file",
		},
		{
			name:          "path without leading slash",
			caseSensitive: false,
			path:          "path/to/file",
			expected:      "/path/to/file",
		},
		{
			name:          "uppercase path (case-insensitive)",
			caseSensitive: false,
			path:          "/PATH/TO/FILE",
			expected:      "/path/to/file",
		},
		{
			name:          "uppercase path (case-sensitive)",
			caseSensitive: true,
			path:          "/PATH/TO/FILE",
			expected:      "/PATH/TO/FILE",
		},
		{
			name:          "multiple slashes",
			caseSensitive: false,
			path:          "/path///to////file",
			expected:      "/path/to/file",
		},
		{
			name:          "trailing slash",
			caseSensitive: false,
			path:          "/path/to/dir/",
			expected:      "/path/to/dir",
		},
		{
			name:          "root path",
			caseSensitive: false,
			path:          "/",
			expected:      "/",
		},
		{
			name:          "empty becomes root",
			caseSensitive: false,
			path:          "",
			expected:      "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pn := newPathNormalizer(tt.caseSensitive)
			result := pn.normalize(tt.path)

			if result != tt.expected {
				t.Errorf("normalize(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestPathNormalizer_join(t *testing.T) {
	tests := []struct {
		name     string
		elements []string
		expected string
	}{
		{
			name:     "simple join",
			elements: []string{"/path", "to", "file"},
			expected: "/path/to/file",
		},
		{
			name:     "join treats absolute-looking paths as relative",
			elements: []string{"/path", "/to", "file"},
			expected: "/path/to/file", // path.Join treats "/to" as relative "to"
		},
		{
			name:     "join with ..",
			elements: []string{"/path", "to", "..", "file"},
			expected: "/path/file",
		},
		{
			name:     "join single element",
			elements: []string{"/path"},
			expected: "/path",
		},
		{
			name:     "join empty strings",
			elements: []string{"", "", ""},
			expected: "/", // normalize converts "." to "/"
		},
	}

	pn := newPathNormalizer(false)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pn.join(tt.elements...)

			if result != tt.expected {
				t.Errorf("join(%v) = %q, want %q", tt.elements, result, tt.expected)
			}
		})
	}
}

func TestPathNormalizer_dir(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/path/to/file", "/path/to"},
		{"/path/to/dir/", "/path/to"},
		{"/path", "/"},
		{"/", "/"},
		{"file", "/"},
	}

	pn := newPathNormalizer(false)

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := pn.dir(tt.path)

			if result != tt.expected {
				t.Errorf("dir(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestPathNormalizer_base(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/path/to/file", "file"},
		{"/path/to/dir/", "dir"},
		{"/file", "file"},
		{"/", "/"},
		{"file", "file"},
	}

	pn := newPathNormalizer(false)

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := pn.base(tt.path)

			if result != tt.expected {
				t.Errorf("base(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestPathNormalizer_split(t *testing.T) {
	tests := []struct {
		path        string
		expectedDir string
		expectedFile string
	}{
		{"/path/to/file", "/path/to/", "file"},
		{"/path/to/dir/", "/path/to/", "dir"},
		{"/file", "/", "file"},
		{"/", "/", ""},
	}

	pn := newPathNormalizer(false)

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			dir, file := pn.split(tt.path)

			if dir != tt.expectedDir {
				t.Errorf("split(%q) dir = %q, want %q", tt.path, dir, tt.expectedDir)
			}
			if file != tt.expectedFile {
				t.Errorf("split(%q) file = %q, want %q", tt.path, file, tt.expectedFile)
			}
		})
	}
}

func TestIsAbs(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/path/to/file", true},
		{"\\path\\to\\file", true},
		{"path/to/file", false},
		{"./path", false},
		{"", false},
		{"/", true},
		{"\\", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := isAbs(tt.path)

			if result != tt.expected {
				t.Errorf("isAbs(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid path",
			path:    "/path/to/file",
			wantErr: false,
		},
		{
			name:    "valid windows path",
			path:    "\\path\\to\\file",
			wantErr: false,
		},
		{
			name:    "valid relative path",
			path:    "path/to/file",
			wantErr: false,
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
		},
		{
			name:    "path with null byte",
			path:    "/path/to\x00/file",
			wantErr: true,
		},
		{
			name:    "path traversal with leading ..",
			path:    "../../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "path traversal in middle (becomes /etc/passwd which is valid)",
			path:    "/path/../../etc/passwd",
			wantErr: false, // After cleaning, becomes /etc/passwd which doesn't escape
		},
		{
			name:    "safe path with ..",
			path:    "/path/to/../file",
			wantErr: false,
		},
		{
			name:    "path with . is safe",
			path:    "/path/./to/file",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePath(tt.path)

			if tt.wantErr && err == nil {
				t.Errorf("validatePath(%q) expected error, got nil", tt.path)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validatePath(%q) unexpected error = %v", tt.path, err)
			}
		})
	}
}

func TestToSMBPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/path/to/file", "path\\to\\file"},
		{"/", ""},
		{"/file", "file"},
		{"/path/to/dir/", "path\\to\\dir\\"}, // Preserves trailing backslash
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := toSMBPath(tt.path)

			if result != tt.expected {
				t.Errorf("toSMBPath(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestFromSMBPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"path\\to\\file", "/path/to/file"},
		{"", "/"},
		{"file", "/file"},
		{"path\\to\\dir\\", "/path/to/dir"},
		{"\\path\\to\\file", "/path/to/file"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := fromSMBPath(tt.path)

			if result != tt.expected {
				t.Errorf("fromSMBPath(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestPathRoundTrip(t *testing.T) {
	// Test that converting to SMB and back preserves the path (modulo normalization)
	tests := []string{
		"/path/to/file",
		"/path/to/dir",
		"/file",
	}

	for _, original := range tests {
		t.Run(original, func(t *testing.T) {
			smbPath := toSMBPath(original)
			restored := fromSMBPath(smbPath)

			if restored != original {
				t.Errorf("round trip failed: %q -> %q -> %q", original, smbPath, restored)
			}
		})
	}
}
