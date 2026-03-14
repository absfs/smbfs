package smbfs

import "sync"

// LockManager provides advisory byte-range locking for files.
// This implements in-memory locks since absfs doesn't have native lock support.
type LockManager struct {
	mu    sync.Mutex
	locks map[string][]*fileLock // path -> locks
}

// fileLock represents a single byte-range lock on a file
type fileLock struct {
	FileID    FileID
	Offset    uint64
	Length    uint64
	Exclusive bool
}

// NewLockManager creates a new lock manager
func NewLockManager() *LockManager {
	return &LockManager{
		locks: make(map[string][]*fileLock),
	}
}

// Lock attempts to acquire a byte-range lock.
// Returns true if the lock was acquired, false if there is a conflict.
func (lm *LockManager) Lock(path string, fileID FileID, offset, length uint64, exclusive, failImmediate bool) bool {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Check for conflicts with existing locks
	existing := lm.locks[path]
	for _, lock := range existing {
		if !lm.overlaps(lock, offset, length) {
			continue
		}
		// Same file handle can upgrade/downgrade locks
		if lock.FileID == fileID {
			continue
		}
		// Shared locks don't conflict with other shared locks
		if !lock.Exclusive && !exclusive {
			continue
		}
		// Conflict found
		if failImmediate {
			return false
		}
		// Without FAIL_IMMEDIATELY, we should block, but for simplicity
		// we return failure (blocking locks would require goroutine coordination)
		return false
	}

	// No conflict, add the lock
	lm.locks[path] = append(lm.locks[path], &fileLock{
		FileID:    fileID,
		Offset:    offset,
		Length:    length,
		Exclusive: exclusive,
	})

	return true
}

// Unlock removes a byte-range lock.
func (lm *LockManager) Unlock(path string, fileID FileID, offset, length uint64) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	locks := lm.locks[path]
	for i, lock := range locks {
		if lock.FileID == fileID && lock.Offset == offset && lock.Length == length {
			lm.locks[path] = append(locks[:i], locks[i+1:]...)
			break
		}
	}
	if len(lm.locks[path]) == 0 {
		delete(lm.locks, path)
	}
}

// ReleaseAll removes all locks held by a specific file handle.
func (lm *LockManager) ReleaseAll(path string, fileID FileID) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	locks := lm.locks[path]
	n := 0
	for _, lock := range locks {
		if lock.FileID != fileID {
			locks[n] = lock
			n++
		}
	}
	if n == 0 {
		delete(lm.locks, path)
	} else {
		lm.locks[path] = locks[:n]
	}
}

// ReleaseByPath removes all locks for a given path.
func (lm *LockManager) ReleaseByPath(path string) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	delete(lm.locks, path)
}

// overlaps checks if a lock overlaps with a given byte range
func (lm *LockManager) overlaps(lock *fileLock, offset, length uint64) bool {
	lockEnd := lock.Offset + lock.Length
	rangeEnd := offset + length

	// Handle overflow / max range
	if lock.Length == 0 {
		lockEnd = lock.Offset
	}
	if length == 0 {
		rangeEnd = offset
	}

	// Check for zero-length (point) locks
	if lock.Length == 0 || length == 0 {
		return false
	}

	return lock.Offset < rangeEnd && offset < lockEnd
}

// Stats returns lock statistics
func (lm *LockManager) Stats() LockStats {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	totalLocks := 0
	for _, locks := range lm.locks {
		totalLocks += len(locks)
	}

	return LockStats{
		LockedFiles: len(lm.locks),
		TotalLocks:  totalLocks,
	}
}

// LockStats provides statistics about lock usage
type LockStats struct {
	LockedFiles int
	TotalLocks  int
}
