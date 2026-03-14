package smbfs

import "testing"

func TestLockManager_BasicLockUnlock(t *testing.T) {
	lm := NewLockManager()

	fid := FileID{Persistent: 1, Volatile: 1}

	// Lock should succeed
	if !lm.Lock("/test.txt", fid, 0, 100, true, true) {
		t.Fatal("expected lock to succeed")
	}

	// Unlock should work
	lm.Unlock("/test.txt", fid, 0, 100)

	// Lock again should succeed after unlock
	if !lm.Lock("/test.txt", fid, 0, 100, true, true) {
		t.Fatal("expected lock to succeed after unlock")
	}

	stats := lm.Stats()
	if stats.TotalLocks != 1 {
		t.Errorf("expected 1 lock, got %d", stats.TotalLocks)
	}
	if stats.LockedFiles != 1 {
		t.Errorf("expected 1 locked file, got %d", stats.LockedFiles)
	}
}

func TestLockManager_ExclusiveConflict(t *testing.T) {
	lm := NewLockManager()

	fid1 := FileID{Persistent: 1, Volatile: 1}
	fid2 := FileID{Persistent: 2, Volatile: 2}

	// First exclusive lock should succeed
	if !lm.Lock("/test.txt", fid1, 0, 100, true, true) {
		t.Fatal("expected first lock to succeed")
	}

	// Second overlapping exclusive lock should fail
	if lm.Lock("/test.txt", fid2, 50, 100, true, true) {
		t.Fatal("expected second lock to fail due to conflict")
	}

	// Non-overlapping lock should succeed
	if !lm.Lock("/test.txt", fid2, 200, 100, true, true) {
		t.Fatal("expected non-overlapping lock to succeed")
	}
}

func TestLockManager_SharedLocks(t *testing.T) {
	lm := NewLockManager()

	fid1 := FileID{Persistent: 1, Volatile: 1}
	fid2 := FileID{Persistent: 2, Volatile: 2}

	// First shared lock
	if !lm.Lock("/test.txt", fid1, 0, 100, false, true) {
		t.Fatal("expected first shared lock to succeed")
	}

	// Second shared lock on same range should succeed
	if !lm.Lock("/test.txt", fid2, 0, 100, false, true) {
		t.Fatal("expected second shared lock to succeed")
	}

	// Exclusive lock on same range should fail
	fid3 := FileID{Persistent: 3, Volatile: 3}
	if lm.Lock("/test.txt", fid3, 0, 100, true, true) {
		t.Fatal("expected exclusive lock to fail against shared locks")
	}
}

func TestLockManager_SameHandle(t *testing.T) {
	lm := NewLockManager()

	fid := FileID{Persistent: 1, Volatile: 1}

	// Lock
	if !lm.Lock("/test.txt", fid, 0, 100, true, true) {
		t.Fatal("expected lock to succeed")
	}

	// Same handle can re-lock (upgrade/downgrade)
	if !lm.Lock("/test.txt", fid, 0, 100, false, true) {
		t.Fatal("expected same handle to re-lock")
	}
}

func TestLockManager_ReleaseAll(t *testing.T) {
	lm := NewLockManager()

	fid := FileID{Persistent: 1, Volatile: 1}

	lm.Lock("/test.txt", fid, 0, 100, true, true)
	lm.Lock("/test.txt", fid, 100, 100, true, true)
	lm.Lock("/test.txt", fid, 200, 100, true, true)

	if stats := lm.Stats(); stats.TotalLocks != 3 {
		t.Errorf("expected 3 locks, got %d", stats.TotalLocks)
	}

	lm.ReleaseAll("/test.txt", fid)

	if stats := lm.Stats(); stats.TotalLocks != 0 {
		t.Errorf("expected 0 locks after release, got %d", stats.TotalLocks)
	}
}

func TestLockManager_ReleaseByPath(t *testing.T) {
	lm := NewLockManager()

	fid1 := FileID{Persistent: 1, Volatile: 1}
	fid2 := FileID{Persistent: 2, Volatile: 2}

	lm.Lock("/test1.txt", fid1, 0, 100, true, true)
	lm.Lock("/test2.txt", fid2, 0, 100, true, true)

	lm.ReleaseByPath("/test1.txt")

	stats := lm.Stats()
	if stats.LockedFiles != 1 {
		t.Errorf("expected 1 locked file, got %d", stats.LockedFiles)
	}
}

func TestLockManager_NoOverlapZeroLength(t *testing.T) {
	lm := NewLockManager()

	fid1 := FileID{Persistent: 1, Volatile: 1}
	fid2 := FileID{Persistent: 2, Volatile: 2}

	// Zero-length locks should not conflict
	if !lm.Lock("/test.txt", fid1, 0, 0, true, true) {
		t.Fatal("expected zero-length lock to succeed")
	}
	if !lm.Lock("/test.txt", fid2, 0, 0, true, true) {
		t.Fatal("expected second zero-length lock to succeed")
	}
}
