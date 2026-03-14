package smbfs

// Oplock levels
const (
	SMB2_OPLOCK_LEVEL_NONE      uint8 = 0x00
	SMB2_OPLOCK_LEVEL_II        uint8 = 0x01 // Shared (read cache)
	SMB2_OPLOCK_LEVEL_EXCLUSIVE uint8 = 0x08 // Exclusive (read+write cache)
	SMB2_OPLOCK_LEVEL_BATCH     uint8 = 0x09 // Batch (read+write+handle cache)
	SMB2_OPLOCK_LEVEL_LEASE     uint8 = 0xFF // Directory lease
)

// handleOplockBreak processes an SMB2 OPLOCK_BREAK acknowledgment.
// When the server sends an oplock break notification, the client responds
// with this acknowledgment. Since we don't grant oplocks (always set to NONE),
// receiving this is unexpected but we handle it gracefully.
func (h *SMBHandler) handleOplockBreak(state *connState, msg *SMB2Message) ([]byte, NTStatus) {
	// Validate session and tree
	_, _, status := h.validateTree(msg.Header)
	if status != STATUS_SUCCESS {
		return h.buildErrorResponse(), status
	}

	// Parse request
	if len(msg.Payload) < 24 {
		return h.buildErrorResponse(), STATUS_INVALID_PARAMETER
	}

	r := NewByteReader(msg.Payload)
	structSize := r.ReadUint16()
	if structSize != 24 {
		return h.buildErrorResponse(), STATUS_INVALID_PARAMETER
	}

	oplockLevel := r.ReadOneByte()
	_ = r.ReadOneByte() // Reserved
	_ = r.ReadUint32()  // Reserved2
	fileID := r.ReadFileID()

	h.server.logger.Debug("OPLOCK_BREAK: fileID=%d/%d level=%d",
		fileID.Persistent, fileID.Volatile, oplockLevel)

	// Build response - acknowledge with NONE level since we don't support oplocks
	w := NewByteWriter(24)
	w.WriteUint16(24)                  // StructureSize
	w.WriteOneByte(SMB2_OPLOCK_LEVEL_NONE) // OplockLevel
	w.WriteOneByte(0)                  // Reserved
	w.WriteUint32(0)                   // Reserved2
	w.WriteFileID(fileID)              // FileId

	return w.Bytes(), STATUS_SUCCESS
}
