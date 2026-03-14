package smbfs

// SMB2 CHANGE_NOTIFY completion filter flags
const (
	FILE_NOTIFY_CHANGE_FILE_NAME    uint32 = 0x00000001
	FILE_NOTIFY_CHANGE_DIR_NAME     uint32 = 0x00000002
	FILE_NOTIFY_CHANGE_ATTRIBUTES   uint32 = 0x00000020
	FILE_NOTIFY_CHANGE_SIZE         uint32 = 0x00000008
	FILE_NOTIFY_CHANGE_LAST_WRITE   uint32 = 0x00000010
	FILE_NOTIFY_CHANGE_LAST_ACCESS  uint32 = 0x00000020
	FILE_NOTIFY_CHANGE_CREATION     uint32 = 0x00000040
	FILE_NOTIFY_CHANGE_EA           uint32 = 0x00000080
	FILE_NOTIFY_CHANGE_SECURITY     uint32 = 0x00000100
	FILE_NOTIFY_CHANGE_STREAM_NAME  uint32 = 0x00000200
	FILE_NOTIFY_CHANGE_STREAM_SIZE  uint32 = 0x00000400
	FILE_NOTIFY_CHANGE_STREAM_WRITE uint32 = 0x00000800
)

// Notify action constants
const (
	FILE_ACTION_ADDED            uint32 = 0x00000001
	FILE_ACTION_REMOVED          uint32 = 0x00000002
	FILE_ACTION_MODIFIED         uint32 = 0x00000003
	FILE_ACTION_RENAMED_OLD_NAME uint32 = 0x00000004
	FILE_ACTION_RENAMED_NEW_NAME uint32 = 0x00000005
)

// handleChangeNotify processes an SMB2 CHANGE_NOTIFY request.
// Change notifications allow clients to watch for filesystem changes.
// Since absfs doesn't provide a native watch mechanism, we return
// STATUS_NOT_SUPPORTED to indicate that real-time notifications
// are not available. Clients will fall back to polling.
func (h *SMBHandler) handleChangeNotify(state *connState, msg *SMB2Message) ([]byte, NTStatus) {
	// Validate session and tree
	session, tree, status := h.validateTree(msg.Header)
	if status != STATUS_SUCCESS {
		return h.buildErrorResponse(), status
	}

	// Parse request
	if len(msg.Payload) < 32 {
		return h.buildErrorResponse(), STATUS_INVALID_PARAMETER
	}

	r := NewByteReader(msg.Payload)
	structSize := r.ReadUint16()
	if structSize != 32 {
		return h.buildErrorResponse(), STATUS_INVALID_PARAMETER
	}

	flags := r.ReadUint16()
	_ = r.ReadUint32() // OutputBufferLength
	fileID := r.ReadFileID()
	completionFilter := r.ReadUint32()

	// Get file handle to validate it
	of := tree.Share.fileHandles.GetByTree(fileID, tree.ID, session.ID)
	if of == nil {
		return h.buildErrorResponse(), STATUS_FILE_CLOSED
	}

	// Must be a directory
	if !of.IsDir {
		return h.buildErrorResponse(), STATUS_INVALID_PARAMETER
	}

	watchSubtree := flags&0x0001 != 0
	h.server.logger.Debug("CHANGE_NOTIFY: %s filter=0x%x subtree=%v",
		of.Path, completionFilter, watchSubtree)

	// Return NOT_SUPPORTED - clients will fall back to polling.
	// A full implementation would register a watcher and hold the request
	// open until a change occurs or the client cancels.
	return h.buildErrorResponse(), STATUS_NOT_SUPPORTED
}
