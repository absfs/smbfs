package smbfs

// SMB2 LOCK constants
const (
	SMB2_LOCKFLAG_SHARED_LOCK       uint32 = 0x00000001
	SMB2_LOCKFLAG_EXCLUSIVE_LOCK    uint32 = 0x00000002
	SMB2_LOCKFLAG_UNLOCK            uint32 = 0x00000004
	SMB2_LOCKFLAG_FAIL_IMMEDIATELY  uint32 = 0x00000010
)

// LockEntry represents a single byte-range lock
type LockEntry struct {
	Offset uint64
	Length uint64
	Flags  uint32
}

// handleLock processes an SMB2 LOCK request
// Byte-range locking is used by clients for file region coordination.
// Since absfs doesn't have native lock support, we implement advisory locks
// tracked in-memory per file handle.
func (h *SMBHandler) handleLock(state *connState, msg *SMB2Message) ([]byte, NTStatus) {
	// Validate session and tree
	session, tree, status := h.validateTree(msg.Header)
	if status != STATUS_SUCCESS {
		return h.buildErrorResponse(), status
	}

	// Parse request - minimum size is 48 bytes
	if len(msg.Payload) < 48 {
		return h.buildErrorResponse(), STATUS_INVALID_PARAMETER
	}

	r := NewByteReader(msg.Payload)
	structSize := r.ReadUint16()
	if structSize != 48 {
		return h.buildErrorResponse(), STATUS_INVALID_PARAMETER
	}

	lockCount := r.ReadUint16()
	lockSequence := r.ReadUint32()
	fileID := r.ReadFileID()

	_ = lockSequence

	// Get file handle
	of := tree.Share.fileHandles.GetByTree(fileID, tree.ID, session.ID)
	if of == nil {
		return h.buildErrorResponse(), STATUS_FILE_CLOSED
	}

	h.server.logger.Debug("LOCK: %s lockCount=%d", of.Path, lockCount)

	// Parse lock entries (each is 24 bytes: offset(8) + length(8) + flags(4) + reserved(4))
	for i := uint16(0); i < lockCount; i++ {
		if r.Remaining() < 24 {
			return h.buildErrorResponse(), STATUS_INVALID_PARAMETER
		}

		offset := r.ReadUint64()
		length := r.ReadUint64()
		flags := r.ReadUint32()
		_ = r.ReadUint32() // Reserved

		entry := LockEntry{
			Offset: offset,
			Length: length,
			Flags:  flags,
		}

		if entry.Flags&SMB2_LOCKFLAG_UNLOCK != 0 {
			// Unlock request
			h.server.lockManager.Unlock(of.Path, fileID, entry.Offset, entry.Length)
			h.server.logger.Debug("LOCK: unlocked %s offset=%d length=%d", of.Path, offset, length)
		} else {
			// Lock request
			exclusive := entry.Flags&SMB2_LOCKFLAG_EXCLUSIVE_LOCK != 0
			failImmediate := entry.Flags&SMB2_LOCKFLAG_FAIL_IMMEDIATELY != 0

			ok := h.server.lockManager.Lock(of.Path, fileID, entry.Offset, entry.Length, exclusive, failImmediate)
			if !ok {
				h.server.logger.Debug("LOCK: conflict on %s offset=%d length=%d", of.Path, offset, length)
				return h.buildErrorResponse(), STATUS_LOCK_NOT_GRANTED
			}
			h.server.logger.Debug("LOCK: locked %s offset=%d length=%d exclusive=%v",
				of.Path, offset, length, exclusive)
		}
	}

	// Build response (structure size 4)
	w := NewByteWriter(4)
	w.WriteUint16(4) // StructureSize
	w.WriteUint16(0) // Reserved

	return w.Bytes(), STATUS_SUCCESS
}

// STATUS_LOCK_NOT_GRANTED is returned when a lock cannot be acquired
const STATUS_LOCK_NOT_GRANTED NTStatus = 0xC0000055
