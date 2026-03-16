package smbfs

import (
	"bytes"
	"testing"
)

// ---------------------------------------------------------------------------
// ByteReader tests
// ---------------------------------------------------------------------------

func TestEncodingByteReaderSkip(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	r := NewByteReader(data)

	r.Skip(2)
	if r.Position() != 2 {
		t.Errorf("after Skip(2): Position() = %d, want 2", r.Position())
	}
	if r.Remaining() != 3 {
		t.Errorf("after Skip(2): Remaining() = %d, want 3", r.Remaining())
	}

	// Skip past end — position moves beyond data length.
	r.Skip(100)
	if r.Position() != 102 {
		t.Errorf("after Skip(100): Position() = %d, want 102", r.Position())
	}
	// Remaining() returns negative when position exceeds data length.
	// Reads will still fail gracefully (return nil / zero).
	if r.Remaining() != len(data)-102 {
		t.Errorf("after Skip past end: Remaining() = %d, want %d", r.Remaining(), len(data)-102)
	}
}

func TestEncodingByteReaderSeek(t *testing.T) {
	data := make([]byte, 10)
	r := NewByteReader(data)

	r.Seek(5)
	if r.Position() != 5 {
		t.Errorf("after Seek(5): Position() = %d, want 5", r.Position())
	}

	r.Seek(0)
	if r.Position() != 0 {
		t.Errorf("after Seek(0): Position() = %d, want 0", r.Position())
	}

	// Seek past end
	r.Seek(999)
	if r.Position() != 999 {
		t.Errorf("after Seek(999): Position() = %d, want 999", r.Position())
	}
}

func TestEncodingByteReaderReadBytes(t *testing.T) {
	data := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	r := NewByteReader(data)

	got := r.ReadBytes(2)
	if !bytes.Equal(got, []byte{0xAA, 0xBB}) {
		t.Errorf("ReadBytes(2) = %v, want [0xAA, 0xBB]", got)
	}
	if r.Position() != 2 {
		t.Errorf("Position() after ReadBytes(2) = %d, want 2", r.Position())
	}

	// Read remaining
	got = r.ReadBytes(2)
	if !bytes.Equal(got, []byte{0xCC, 0xDD}) {
		t.Errorf("ReadBytes(2) = %v, want [0xCC, 0xDD]", got)
	}

	// Read past end returns nil
	got = r.ReadBytes(1)
	if got != nil {
		t.Errorf("ReadBytes past end = %v, want nil", got)
	}
}

func TestEncodingByteReaderReadOneByte(t *testing.T) {
	data := []byte{0x42, 0xFF}
	r := NewByteReader(data)

	b := r.ReadOneByte()
	if b != 0x42 {
		t.Errorf("ReadOneByte() = 0x%02X, want 0x42", b)
	}

	b = r.ReadOneByte()
	if b != 0xFF {
		t.Errorf("ReadOneByte() = 0x%02X, want 0xFF", b)
	}

	// Read from empty returns 0
	b = r.ReadOneByte()
	if b != 0 {
		t.Errorf("ReadOneByte() from empty = 0x%02X, want 0x00", b)
	}
}

func TestEncodingByteReaderReadFileID(t *testing.T) {
	// Build a 16-byte FileID: Persistent=0x0102030405060708, Volatile=0x1112131415161718
	w := NewByteWriter(16)
	w.WriteUint64(0x0102030405060708)
	w.WriteUint64(0x1112131415161718)

	r := NewByteReader(w.Bytes())
	fid := r.ReadFileID()

	if fid.Persistent != 0x0102030405060708 {
		t.Errorf("Persistent = 0x%X, want 0x0102030405060708", fid.Persistent)
	}
	if fid.Volatile != 0x1112131415161718 {
		t.Errorf("Volatile = 0x%X, want 0x1112131415161718", fid.Volatile)
	}

	// Too short — both fields should be 0
	r2 := NewByteReader([]byte{0x01, 0x02, 0x03})
	fid2 := r2.ReadFileID()
	if fid2.Persistent != 0 || fid2.Volatile != 0 {
		t.Errorf("short FileID: got {%d, %d}, want {0, 0}", fid2.Persistent, fid2.Volatile)
	}
}

func TestEncodingByteReaderReadGUID(t *testing.T) {
	var expected [16]byte
	for i := range expected {
		expected[i] = byte(i + 1)
	}

	r := NewByteReader(expected[:])
	guid := r.ReadGUID()
	if guid != expected {
		t.Errorf("ReadGUID() = %v, want %v", guid, expected)
	}

	// Too short — should return zero GUID (ReadBytes returns nil, copy is no-op)
	r2 := NewByteReader([]byte{0x01, 0x02})
	guid2 := r2.ReadGUID()
	var zero [16]byte
	if guid2 != zero {
		t.Errorf("short ReadGUID() = %v, want zero GUID", guid2)
	}
}

func TestEncodingByteReaderReadUTF16String(t *testing.T) {
	// "Hello" in UTF-16LE
	encoded := EncodeStringToUTF16LE("Hello")
	r := NewByteReader(encoded)

	got := r.ReadUTF16String(len(encoded))
	if got != "Hello" {
		t.Errorf("ReadUTF16String() = %q, want %q", got, "Hello")
	}

	// Zero length
	r2 := NewByteReader(encoded)
	got2 := r2.ReadUTF16String(0)
	if got2 != "" {
		t.Errorf("ReadUTF16String(0) = %q, want empty", got2)
	}

	// Odd length — truncates to even
	data := []byte{0x48, 0x00, 0x65} // 'H' + partial
	r3 := NewByteReader(data)
	got3 := r3.ReadUTF16String(3)
	if got3 != "H" {
		t.Errorf("ReadUTF16String(odd) = %q, want %q", got3, "H")
	}
}

// ---------------------------------------------------------------------------
// ByteWriter tests
// ---------------------------------------------------------------------------

func TestEncodingByteWriterReset(t *testing.T) {
	w := NewByteWriter(16)
	w.WriteUint32(0xDEADBEEF)
	if w.Len() != 4 {
		t.Fatalf("Len() before reset = %d, want 4", w.Len())
	}

	w.Reset()
	if w.Len() != 0 {
		t.Errorf("Len() after reset = %d, want 0", w.Len())
	}
	if len(w.Bytes()) != 0 {
		t.Errorf("Bytes() after reset has length %d, want 0", len(w.Bytes()))
	}
}

func TestEncodingByteWriterWriteBytes(t *testing.T) {
	w := NewByteWriter(16)
	input := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	w.WriteBytes(input)

	if !bytes.Equal(w.Bytes(), input) {
		t.Errorf("Bytes() = %v, want %v", w.Bytes(), input)
	}
}

func TestEncodingByteWriterWriteOneByte(t *testing.T) {
	w := NewByteWriter(4)
	w.WriteOneByte(0x42)
	w.WriteOneByte(0xFF)

	expected := []byte{0x42, 0xFF}
	if !bytes.Equal(w.Bytes(), expected) {
		t.Errorf("Bytes() = %v, want %v", w.Bytes(), expected)
	}
}

func TestEncodingByteWriterWriteFileID(t *testing.T) {
	fid := FileID{Persistent: 0xAAAAAAAABBBBBBBB, Volatile: 0xCCCCCCCCDDDDDDDD}
	w := NewByteWriter(16)
	w.WriteFileID(fid)

	r := NewByteReader(w.Bytes())
	got := r.ReadFileID()
	if got != fid {
		t.Errorf("round-trip FileID: got %+v, want %+v", got, fid)
	}
}

func TestEncodingByteWriterWriteGUID(t *testing.T) {
	var guid [16]byte
	for i := range guid {
		guid[i] = byte(0xA0 + i)
	}

	w := NewByteWriter(16)
	w.WriteGUID(guid)

	r := NewByteReader(w.Bytes())
	got := r.ReadGUID()
	if got != guid {
		t.Errorf("round-trip GUID: got %v, want %v", got, guid)
	}
}

func TestEncodingByteWriterWriteUTF16String(t *testing.T) {
	tests := []string{"Hello", "World!", "", "日本語", "a"}
	for _, s := range tests {
		w := NewByteWriter(64)
		w.WriteUTF16String(s)
		got := DecodeUTF16LEToString(w.Bytes())
		if got != s {
			t.Errorf("round-trip UTF16 %q: got %q", s, got)
		}
	}
}

func TestEncodingByteWriterWriteZeros(t *testing.T) {
	w := NewByteWriter(16)
	w.WriteOneByte(0xFF) // sentinel
	w.WriteZeros(5)

	data := w.Bytes()
	if len(data) != 6 {
		t.Fatalf("Len() = %d, want 6", len(data))
	}
	for i := 1; i < 6; i++ {
		if data[i] != 0 {
			t.Errorf("byte[%d] = 0x%02X, want 0x00", i, data[i])
		}
	}

	// WriteZeros(0) should be a no-op
	before := w.Len()
	w.WriteZeros(0)
	if w.Len() != before {
		t.Errorf("WriteZeros(0) changed length from %d to %d", before, w.Len())
	}
}

func TestEncodingByteWriterWritePadTo8(t *testing.T) {
	tests := []struct {
		name     string
		initial  int // number of bytes to write before padding
		wantLen  int // expected total length after padding
	}{
		{"0 bytes (already aligned)", 0, 0},
		{"1 byte", 1, 8},
		{"2 bytes", 2, 8},
		{"3 bytes", 3, 8},
		{"7 bytes", 7, 8},
		{"8 bytes (already aligned)", 8, 8},
		{"9 bytes", 9, 16},
		{"15 bytes", 15, 16},
		{"16 bytes (already aligned)", 16, 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewByteWriter(32)
			for i := 0; i < tt.initial; i++ {
				w.WriteOneByte(0x01)
			}
			w.WritePadTo8()
			if w.Len() != tt.wantLen {
				t.Errorf("after WritePadTo8(): Len() = %d, want %d", w.Len(), tt.wantLen)
			}
			// Verify padding bytes are zeros
			data := w.Bytes()
			for i := tt.initial; i < len(data); i++ {
				if data[i] != 0 {
					t.Errorf("padding byte[%d] = 0x%02X, want 0x00", i, data[i])
				}
			}
		})
	}
}

func TestEncodingByteWriterSetUint16At(t *testing.T) {
	w := NewByteWriter(16)
	w.WriteZeros(8)

	w.SetUint16At(2, 0xBEEF)

	r := NewByteReader(w.Bytes())
	r.Skip(2)
	got := r.ReadUint16()
	if got != 0xBEEF {
		t.Errorf("SetUint16At: got 0x%04X, want 0xBEEF", got)
	}

	// Verify surrounding bytes are still zero
	data := w.Bytes()
	if data[0] != 0 || data[1] != 0 || data[4] != 0 || data[5] != 0 {
		t.Errorf("SetUint16At corrupted adjacent bytes: %v", data)
	}

	// Set past end should be a no-op
	w.SetUint16At(100, 0x1234)
	if w.Len() != 8 {
		t.Errorf("SetUint16At past end changed length to %d", w.Len())
	}
}

func TestEncodingByteWriterSetUint32At(t *testing.T) {
	w := NewByteWriter(16)
	w.WriteZeros(12)

	w.SetUint32At(4, 0xDEADBEEF)

	r := NewByteReader(w.Bytes())
	r.Skip(4)
	got := r.ReadUint32()
	if got != 0xDEADBEEF {
		t.Errorf("SetUint32At: got 0x%08X, want 0xDEADBEEF", got)
	}

	// Verify surrounding bytes are still zero
	data := w.Bytes()
	if data[0] != 0 || data[1] != 0 || data[8] != 0 || data[9] != 0 {
		t.Errorf("SetUint32At corrupted adjacent bytes: %v", data)
	}

	// Set past end should be a no-op
	w.SetUint32At(100, 0x12345678)
	if w.Len() != 12 {
		t.Errorf("SetUint32At past end changed length to %d", w.Len())
	}
}

// ---------------------------------------------------------------------------
// Standalone function tests
// ---------------------------------------------------------------------------

func TestEncodingPadTo8ByteBoundary(t *testing.T) {
	tests := []struct {
		offset int
		want   int
	}{
		{0, 0},
		{1, 7},
		{2, 6},
		{3, 5},
		{4, 4},
		{5, 3},
		{6, 2},
		{7, 1},
		{8, 0},
		{9, 7},
		{15, 1},
		{16, 0},
	}
	for _, tt := range tests {
		got := PadTo8ByteBoundary(tt.offset)
		if got != tt.want {
			t.Errorf("PadTo8ByteBoundary(%d) = %d, want %d", tt.offset, got, tt.want)
		}
	}
}

func TestEncodingAlignTo8(t *testing.T) {
	tests := []struct {
		v    int
		want int
	}{
		{0, 0},
		{1, 8},
		{2, 8},
		{7, 8},
		{8, 8},
		{9, 16},
		{15, 16},
		{16, 16},
		{17, 24},
	}
	for _, tt := range tests {
		got := AlignTo8(tt.v)
		if got != tt.want {
			t.Errorf("AlignTo8(%d) = %d, want %d", tt.v, got, tt.want)
		}
	}
}

func TestEncodingNewGUID(t *testing.T) {
	guid := NewGUID()
	// Verify the GUID is a 16-byte value (compile-time guarantee for [16]byte).
	// Current implementation returns all zeros; verify that explicitly.
	var zero [16]byte
	if guid != zero {
		t.Fatalf("NewGUID() returned non-zero value %x, want all zeros (placeholder)", guid)
	}
}

func TestEncodingGUIDToString(t *testing.T) {
	// GUID bytes: the format reverses groups per Microsoft mixed-endian layout.
	// Bytes: [0x01,0x02,0x03,0x04, 0x05,0x06, 0x07,0x08, 0x09,0x0A, 0x0B..0x10]
	// Group 1 (LE uint32): bytes 0-3 → 04030201
	// Group 2 (LE uint16): bytes 4-5 → 0605
	// Group 3 (LE uint16): bytes 6-7 → 0807
	// Group 4 (big-endian): bytes 8-9 → 090a
	// Group 5 (big-endian): bytes 10-15 → 0b0c0d0e0f10
	guid := [16]byte{
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06,
		0x07, 0x08,
		0x09, 0x0A,
		0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	}

	got := GUIDToString(guid)
	want := "04030201-0605-0807-090a-0b0c0d0e0f10"
	if got != want {
		t.Errorf("GUIDToString(%v) = %q, want %q", guid, got, want)
	}

	// All zeros
	var zero [16]byte
	gotZero := GUIDToString(zero)
	wantZero := "00000000-0000-0000-0000-000000000000"
	if gotZero != wantZero {
		t.Errorf("GUIDToString(zero) = %q, want %q", gotZero, wantZero)
	}

	// All 0xFF
	var ff [16]byte
	for i := range ff {
		ff[i] = 0xFF
	}
	gotFF := GUIDToString(ff)
	wantFF := "ffffffff-ffff-ffff-ffff-ffffffffffff"
	if gotFF != wantFF {
		t.Errorf("GUIDToString(0xFF) = %q, want %q", gotFF, wantFF)
	}
}

func TestEncodingHexDigit(t *testing.T) {
	expected := "0123456789abcdef"
	for i := byte(0); i < 16; i++ {
		got := hexDigit(i)
		want := expected[i]
		if got != want {
			t.Errorf("hexDigit(%d) = %c, want %c", i, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// UTF-16 round-trip tests
// ---------------------------------------------------------------------------

func TestEncodingUTF16RoundTrip(t *testing.T) {
	tests := []string{
		"",
		"hello",
		"Hello, World!",
		"日本語テスト",
		"path\\to\\file.txt",
		"abc\x00def", // embedded null
	}

	for _, s := range tests {
		encoded := EncodeStringToUTF16LE(s)
		decoded := DecodeUTF16LEToString(encoded)
		if decoded != s {
			t.Errorf("round-trip %q: got %q", s, decoded)
		}
	}
}

func TestEncodingDecodeUTF16LEEmptyAndNil(t *testing.T) {
	if got := DecodeUTF16LEToString(nil); got != "" {
		t.Errorf("DecodeUTF16LEToString(nil) = %q, want empty", got)
	}
	if got := DecodeUTF16LEToString([]byte{}); got != "" {
		t.Errorf("DecodeUTF16LEToString(empty) = %q, want empty", got)
	}
}

func TestEncodingDecodeUTF16LEWithNullTerminator(t *testing.T) {
	// "Hi" + null terminator in UTF-16LE
	data := []byte{0x48, 0x00, 0x69, 0x00, 0x00, 0x00}
	got := DecodeUTF16LEToString(data)
	if got != "Hi" {
		t.Errorf("DecodeUTF16LEToString with null = %q, want %q", got, "Hi")
	}
}
