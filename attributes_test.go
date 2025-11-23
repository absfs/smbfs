package smbfs

import (
	"io/fs"
	"testing"
)

func TestWindowsAttributes_Flags(t *testing.T) {
	tests := []struct {
		name  string
		attrs uint32
		check func(*WindowsAttributes) bool
		want  bool
	}{
		{
			name:  "hidden attribute set",
			attrs: FILE_ATTRIBUTE_HIDDEN,
			check: (*WindowsAttributes).IsHidden,
			want:  true,
		},
		{
			name:  "hidden attribute not set",
			attrs: FILE_ATTRIBUTE_NORMAL,
			check: (*WindowsAttributes).IsHidden,
			want:  false,
		},
		{
			name:  "system attribute set",
			attrs: FILE_ATTRIBUTE_SYSTEM,
			check: (*WindowsAttributes).IsSystem,
			want:  true,
		},
		{
			name:  "readonly attribute set",
			attrs: FILE_ATTRIBUTE_READONLY,
			check: (*WindowsAttributes).IsReadOnly,
			want:  true,
		},
		{
			name:  "archive attribute set",
			attrs: FILE_ATTRIBUTE_ARCHIVE,
			check: (*WindowsAttributes).IsArchive,
			want:  true,
		},
		{
			name:  "temporary attribute set",
			attrs: FILE_ATTRIBUTE_TEMPORARY,
			check: (*WindowsAttributes).IsTemporary,
			want:  true,
		},
		{
			name:  "compressed attribute set",
			attrs: FILE_ATTRIBUTE_COMPRESSED,
			check: (*WindowsAttributes).IsCompressed,
			want:  true,
		},
		{
			name:  "encrypted attribute set",
			attrs: FILE_ATTRIBUTE_ENCRYPTED,
			check: (*WindowsAttributes).IsEncrypted,
			want:  true,
		},
		{
			name:  "multiple attributes",
			attrs: FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY,
			check: (*WindowsAttributes).IsHidden,
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wa := NewWindowsAttributes(tt.attrs)
			got := tt.check(wa)
			if got != tt.want {
				t.Errorf("check() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWindowsAttributes_Set(t *testing.T) {
	wa := NewWindowsAttributes(FILE_ATTRIBUTE_NORMAL)

	// Set hidden
	wa.SetHidden(true)
	if !wa.IsHidden() {
		t.Error("Expected hidden to be set")
	}

	// Clear hidden
	wa.SetHidden(false)
	if wa.IsHidden() {
		t.Error("Expected hidden to be cleared")
	}

	// Set system
	wa.SetSystem(true)
	if !wa.IsSystem() {
		t.Error("Expected system to be set")
	}

	// Set readonly
	wa.SetReadOnly(true)
	if !wa.IsReadOnly() {
		t.Error("Expected readonly to be set")
	}

	// Set archive
	wa.SetArchive(true)
	if !wa.IsArchive() {
		t.Error("Expected archive to be set")
	}

	// Multiple attributes
	wa = NewWindowsAttributes(FILE_ATTRIBUTE_NORMAL)
	wa.SetHidden(true)
	wa.SetSystem(true)
	wa.SetReadOnly(true)

	if !wa.IsHidden() || !wa.IsSystem() || !wa.IsReadOnly() {
		t.Error("Expected all three attributes to be set")
	}
}

func TestWindowsAttributes_String(t *testing.T) {
	tests := []struct {
		name  string
		attrs uint32
		want  string
	}{
		{
			name:  "normal",
			attrs: FILE_ATTRIBUTE_NORMAL,
			want:  "Normal",
		},
		{
			name:  "hidden",
			attrs: FILE_ATTRIBUTE_HIDDEN,
			want:  "Hidden",
		},
		{
			name:  "system",
			attrs: FILE_ATTRIBUTE_SYSTEM,
			want:  "System",
		},
		{
			name:  "readonly",
			attrs: FILE_ATTRIBUTE_READONLY,
			want:  "ReadOnly",
		},
		{
			name:  "multiple",
			attrs: FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY,
			want:  "ReadOnly, Hidden",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wa := NewWindowsAttributes(tt.attrs)
			got := wa.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAttributesToMode(t *testing.T) {
	tests := []struct {
		name  string
		attrs uint32
		isDir bool
		check func(fs.FileMode) bool
		want  bool
	}{
		{
			name:  "readonly file",
			attrs: FILE_ATTRIBUTE_READONLY,
			isDir: false,
			check: func(m fs.FileMode) bool { return m&0222 == 0 }, // No write bits
			want:  true,
		},
		{
			name:  "directory",
			attrs: FILE_ATTRIBUTE_DIRECTORY,
			isDir: true,
			check: func(m fs.FileMode) bool { return m.IsDir() },
			want:  true,
		},
		{
			name:  "symlink",
			attrs: FILE_ATTRIBUTE_REPARSE_POINT,
			isDir: false,
			check: func(m fs.FileMode) bool { return m&fs.ModeSymlink != 0 },
			want:  true,
		},
		{
			name:  "device",
			attrs: FILE_ATTRIBUTE_DEVICE,
			isDir: false,
			check: func(m fs.FileMode) bool { return m&fs.ModeDevice != 0 },
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode := attributesToMode(tt.attrs, tt.isDir)
			got := tt.check(mode)
			if got != tt.want {
				t.Errorf("check(attributesToMode(%#x, %v)) = %v, want %v (mode: %v)",
					tt.attrs, tt.isDir, got, tt.want, mode)
			}
		})
	}
}

func TestModeToAttributes(t *testing.T) {
	tests := []struct {
		name  string
		mode  fs.FileMode
		check func(uint32) bool
		want  bool
	}{
		{
			name: "readonly (no write permissions)",
			mode: 0444,
			check: func(attrs uint32) bool {
				return attrs&FILE_ATTRIBUTE_READONLY != 0
			},
			want: true,
		},
		{
			name: "writable",
			mode: 0666,
			check: func(attrs uint32) bool {
				return attrs&FILE_ATTRIBUTE_READONLY == 0
			},
			want: true,
		},
		{
			name: "directory",
			mode: fs.ModeDir | 0755,
			check: func(attrs uint32) bool {
				return attrs&FILE_ATTRIBUTE_DIRECTORY != 0
			},
			want: true,
		},
		{
			name: "symlink",
			mode: fs.ModeSymlink | 0777,
			check: func(attrs uint32) bool {
				return attrs&FILE_ATTRIBUTE_REPARSE_POINT != 0
			},
			want: true,
		},
		{
			name: "device",
			mode: fs.ModeDevice | 0666,
			check: func(attrs uint32) bool {
				return attrs&FILE_ATTRIBUTE_DEVICE != 0
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := modeToAttributes(tt.mode)
			got := tt.check(attrs)
			if got != tt.want {
				t.Errorf("check(modeToAttributes(%v)) = %v, want %v (attrs: %#x)",
					tt.mode, got, tt.want, attrs)
			}
		})
	}
}

func TestShareType_String(t *testing.T) {
	tests := []struct {
		shareType ShareType
		want      string
	}{
		{ShareTypeDisk, "Disk"},
		{ShareTypePrintQueue, "Print Queue"},
		{ShareTypeDevice, "Device"},
		{ShareTypeIPC, "IPC"},
		{ShareTypeSpecial, "Special"},
		{ShareTypeTemporary, "Temporary"},
		{ShareType(999), "Unknown(999)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.shareType.String()
			if got != tt.want {
				t.Errorf("ShareType.String() = %q, want %q", got, tt.want)
			}
		})
	}
}
