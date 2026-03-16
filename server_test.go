package smbfs

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/absfs/memfs"
)

// TestNewServer_DefaultOptions tests server creation with default options
func TestNewServer_DefaultOptions(t *testing.T) {
	opts := ServerOptions{}
	srv, err := NewServer(opts)
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}

	if srv == nil {
		t.Fatal("NewServer() returned nil server")
	}

	// Check defaults were applied
	if srv.options.Port != 445 {
		t.Errorf("Port = %d, want 445", srv.options.Port)
	}
	if srv.options.Hostname != "0.0.0.0" {
		t.Errorf("Hostname = %q, want \"0.0.0.0\"", srv.options.Hostname)
	}
	if srv.options.MinDialect != SMB2_0_2 {
		t.Errorf("MinDialect = %v, want SMB2_0_2", srv.options.MinDialect)
	}
	if srv.options.MaxDialect != SMB3_1_1 {
		t.Errorf("MaxDialect = %v, want SMB3_1_1", srv.options.MaxDialect)
	}
	if srv.options.IdleTimeout != 15*time.Minute {
		t.Errorf("IdleTimeout = %v, want 15m", srv.options.IdleTimeout)
	}
	if srv.options.ReadTimeout != 30*time.Second {
		t.Errorf("ReadTimeout = %v, want 30s", srv.options.ReadTimeout)
	}
	if srv.options.WriteTimeout != 30*time.Second {
		t.Errorf("WriteTimeout = %v, want 30s", srv.options.WriteTimeout)
	}
	if srv.options.MaxReadSize != MaxReadSize {
		t.Errorf("MaxReadSize = %d, want %d", srv.options.MaxReadSize, MaxReadSize)
	}
	if srv.options.MaxWriteSize != MaxWriteSize {
		t.Errorf("MaxWriteSize = %d, want %d", srv.options.MaxWriteSize, MaxWriteSize)
	}
}

// TestNewServer_CustomOptions tests server creation with custom options
func TestNewServer_CustomOptions(t *testing.T) {
	opts := ServerOptions{
		Port:            8445,
		Hostname:        "127.0.0.1",
		MinDialect:      SMB2_1,
		MaxDialect:      SMB3_0_2,
		IdleTimeout:     30 * time.Minute,
		ReadTimeout:     60 * time.Second,
		WriteTimeout:    60 * time.Second,
		MaxConnections:  50,
		MaxReadSize:     4 * 1024 * 1024,
		MaxWriteSize:    4 * 1024 * 1024,
		SigningRequired: true,
	}

	srv, err := NewServer(opts)
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}

	// Verify custom options were preserved
	if srv.options.Port != 8445 {
		t.Errorf("Port = %d, want 8445", srv.options.Port)
	}
	if srv.options.Hostname != "127.0.0.1" {
		t.Errorf("Hostname = %q, want \"127.0.0.1\"", srv.options.Hostname)
	}
	if srv.options.MinDialect != SMB2_1 {
		t.Errorf("MinDialect = %v, want SMB2_1", srv.options.MinDialect)
	}
	if srv.options.MaxDialect != SMB3_0_2 {
		t.Errorf("MaxDialect = %v, want SMB3_0_2", srv.options.MaxDialect)
	}
	if srv.options.IdleTimeout != 30*time.Minute {
		t.Errorf("IdleTimeout = %v, want 30m", srv.options.IdleTimeout)
	}
	if srv.options.MaxConnections != 50 {
		t.Errorf("MaxConnections = %d, want 50", srv.options.MaxConnections)
	}
	if srv.options.MaxReadSize != 4*1024*1024 {
		t.Errorf("MaxReadSize = %d, want 4MB", srv.options.MaxReadSize)
	}
	if !srv.options.SigningRequired {
		t.Error("SigningRequired = false, want true")
	}
}

// TestNewServer_ServerGUID tests that server GUID is generated if not provided
func TestNewServer_ServerGUID(t *testing.T) {
	t.Run("auto-generated GUID", func(t *testing.T) {
		opts := ServerOptions{}
		srv, err := NewServer(opts)
		if err != nil {
			t.Fatalf("NewServer() failed: %v", err)
		}

		// Check that GUID was generated (non-zero)
		zeroGUID := [16]byte{}
		if srv.options.ServerGUID == zeroGUID {
			t.Error("ServerGUID was not generated")
		}
	})

	t.Run("custom GUID preserved", func(t *testing.T) {
		customGUID := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		opts := ServerOptions{
			ServerGUID: customGUID,
		}
		srv, err := NewServer(opts)
		if err != nil {
			t.Fatalf("NewServer() failed: %v", err)
		}

		if srv.options.ServerGUID != customGUID {
			t.Errorf("ServerGUID = %v, want %v", srv.options.ServerGUID, customGUID)
		}
	})
}

// TestServer_AddShare tests share registration
func TestServer_AddShare(t *testing.T) {
	srv := setupTestServer(t)

	t.Run("add share success", func(t *testing.T) {
		fs, err := memfs.NewFS()
		if err != nil {
			t.Fatalf("Failed to create memfs: %v", err)
		}
		opts := ShareOptions{
			ShareName: "TestShare",
			SharePath: "/",
		}

		err = srv.AddShare(fs, opts)
		if err != nil {
			t.Fatalf("AddShare() failed: %v", err)
		}

		// Verify share was added
		share := srv.GetShare("TestShare")
		if share == nil {
			t.Fatal("GetShare() returned nil")
		}
		if share.options.ShareName != "TestShare" {
			t.Errorf("ShareName = %q, want \"TestShare\"", share.options.ShareName)
		}
	})

	t.Run("add duplicate share fails", func(t *testing.T) {
		fs, err := memfs.NewFS()
		if err != nil {
			t.Fatalf("Failed to create memfs: %v", err)
		}
		opts := ShareOptions{
			ShareName: "DuplicateShare",
		}

		err = srv.AddShare(fs, opts)
		if err != nil {
			t.Fatalf("First AddShare() failed: %v", err)
		}

		// Try to add same share again
		err = srv.AddShare(fs, opts)
		if err == nil {
			t.Error("AddShare() with duplicate name should fail")
		}
	})

	t.Run("add share without name fails", func(t *testing.T) {
		fs, err := memfs.NewFS()
		if err != nil {
			t.Fatalf("Failed to create memfs: %v", err)
		}
		opts := ShareOptions{}

		err = srv.AddShare(fs, opts)
		if err == nil {
			t.Error("AddShare() without name should fail")
		}
	})
}

// TestServer_RemoveShare tests share removal
func TestServer_RemoveShare(t *testing.T) {
	srv := setupTestServer(t)

	t.Run("remove existing share", func(t *testing.T) {
		fs, err := memfs.NewFS()
		if err != nil {
			t.Fatalf("Failed to create memfs: %v", err)
		}
		opts := ShareOptions{ShareName: "ToRemove"}
		_ = srv.AddShare(fs, opts)

		err = srv.RemoveShare("ToRemove")
		if err != nil {
			t.Fatalf("RemoveShare() failed: %v", err)
		}

		// Verify share was removed
		share := srv.GetShare("ToRemove")
		if share != nil {
			t.Error("Share still exists after removal")
		}
	})

	t.Run("remove non-existent share fails", func(t *testing.T) {
		err := srv.RemoveShare("NonExistent")
		if err == nil {
			t.Error("RemoveShare() for non-existent share should fail")
		}
	})
}

// TestServer_GetShare tests share retrieval
func TestServer_GetShare(t *testing.T) {
	srv := setupTestServer(t)
	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	_ = srv.AddShare(fs, ShareOptions{ShareName: "Share1"})
	_ = srv.AddShare(fs, ShareOptions{ShareName: "Share2"})

	t.Run("get existing share", func(t *testing.T) {
		share := srv.GetShare("Share1")
		if share == nil {
			t.Fatal("GetShare() returned nil")
		}
		if share.options.ShareName != "Share1" {
			t.Errorf("ShareName = %q, want \"Share1\"", share.options.ShareName)
		}
	})

	t.Run("get non-existent share", func(t *testing.T) {
		share := srv.GetShare("NonExistent")
		if share != nil {
			t.Error("GetShare() for non-existent share should return nil")
		}
	})
}

// TestServer_ListShares tests share enumeration
func TestServer_ListShares(t *testing.T) {
	srv := setupTestServer(t)
	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	t.Run("list visible shares only", func(t *testing.T) {
		_ = srv.AddShare(fs, ShareOptions{ShareName: "Public1", Hidden: false})
		_ = srv.AddShare(fs, ShareOptions{ShareName: "Public2", Hidden: false})
		_ = srv.AddShare(fs, ShareOptions{ShareName: "Hidden1", Hidden: true})

		shares := srv.ListShares()
		if len(shares) != 2 {
			t.Errorf("ListShares() returned %d shares, want 2", len(shares))
		}

		// Verify hidden share is not in list
		for _, name := range shares {
			if name == "Hidden1" {
				t.Error("Hidden share appears in ListShares()")
			}
		}
	})

	t.Run("list empty shares", func(t *testing.T) {
		srv := setupTestServer(t)
		shares := srv.ListShares()
		if len(shares) != 0 {
			t.Errorf("ListShares() returned %d shares, want 0", len(shares))
		}
	})
}

// TestSessionManager_CreateSession tests session creation
func TestSessionManager_CreateSession(t *testing.T) {
	mgr := NewSessionManager(15 * time.Minute)

	clientGUID := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	session := mgr.CreateSession(SMB3_1_1, clientGUID, "192.168.1.100")

	if session == nil {
		t.Fatal("CreateSession() returned nil")
	}
	if session.ID == 0 {
		t.Error("Session ID is zero")
	}
	if session.State != SessionStateInProgress {
		t.Errorf("State = %v, want SessionStateInProgress", session.State)
	}
	if session.Dialect != SMB3_1_1 {
		t.Errorf("Dialect = %v, want SMB3_1_1", session.Dialect)
	}
	if session.ClientGUID != clientGUID {
		t.Errorf("ClientGUID = %v, want %v", session.ClientGUID, clientGUID)
	}
	if session.ClientIP != "192.168.1.100" {
		t.Errorf("ClientIP = %q, want \"192.168.1.100\"", session.ClientIP)
	}
}

// TestSessionManager_GetSession tests session retrieval
func TestSessionManager_GetSession(t *testing.T) {
	mgr := NewSessionManager(15 * time.Minute)

	session := mgr.CreateSession(SMB3_1_1, [16]byte{}, "192.168.1.100")
	sessionID := session.ID

	t.Run("get existing session", func(t *testing.T) {
		retrieved := mgr.GetSession(sessionID)
		if retrieved == nil {
			t.Fatal("GetSession() returned nil")
		}
		if retrieved.ID != sessionID {
			t.Errorf("Session ID = %d, want %d", retrieved.ID, sessionID)
		}
	})

	t.Run("get non-existent session", func(t *testing.T) {
		retrieved := mgr.GetSession(99999)
		if retrieved != nil {
			t.Error("GetSession() for non-existent session should return nil")
		}
	})
}

// TestSessionManager_ValidateSession tests session validation
func TestSessionManager_ValidateSession(t *testing.T) {
	mgr := NewSessionManager(15 * time.Minute)

	t.Run("validate session in progress fails", func(t *testing.T) {
		session := mgr.CreateSession(SMB3_1_1, [16]byte{}, "192.168.1.100")

		_, status := mgr.ValidateSession(session.ID)
		if status != STATUS_USER_SESSION_DELETED {
			t.Errorf("ValidateSession() status = %v, want STATUS_USER_SESSION_DELETED", status)
		}
	})

	t.Run("validate valid session succeeds", func(t *testing.T) {
		session := mgr.CreateSession(SMB3_1_1, [16]byte{}, "192.168.1.100")
		session.SetValid("testuser", "DOMAIN", false, nil)

		validated, status := mgr.ValidateSession(session.ID)
		if status != STATUS_SUCCESS {
			t.Errorf("ValidateSession() status = %v, want STATUS_SUCCESS", status)
		}
		if validated == nil {
			t.Fatal("ValidateSession() returned nil session")
		}
		if validated.ID != session.ID {
			t.Errorf("Session ID = %d, want %d", validated.ID, session.ID)
		}
	})

	t.Run("validate non-existent session fails", func(t *testing.T) {
		_, status := mgr.ValidateSession(99999)
		if status != STATUS_USER_SESSION_DELETED {
			t.Errorf("ValidateSession() status = %v, want STATUS_USER_SESSION_DELETED", status)
		}
	})
}

// TestSessionManager_DestroySession tests session destruction
func TestSessionManager_DestroySession(t *testing.T) {
	mgr := NewSessionManager(15 * time.Minute)

	t.Run("destroy existing session", func(t *testing.T) {
		session := mgr.CreateSession(SMB3_1_1, [16]byte{}, "192.168.1.100")
		sessionID := session.ID

		destroyed := mgr.DestroySession(sessionID)
		if destroyed == nil {
			t.Fatal("DestroySession() returned nil")
		}
		if destroyed.ID != sessionID {
			t.Errorf("Destroyed session ID = %d, want %d", destroyed.ID, sessionID)
		}

		// Verify session was removed
		retrieved := mgr.GetSession(sessionID)
		if retrieved != nil {
			t.Error("Session still exists after destruction")
		}
	})

	t.Run("destroy non-existent session", func(t *testing.T) {
		destroyed := mgr.DestroySession(99999)
		if destroyed != nil {
			t.Error("DestroySession() for non-existent session should return nil")
		}
	})
}

// TestSessionManager_CleanupExpired tests expired session cleanup
func TestSessionManager_CleanupExpired(t *testing.T) {
	mgr := NewSessionManager(100 * time.Millisecond)

	// Create sessions
	session1 := mgr.CreateSession(SMB3_1_1, [16]byte{}, "192.168.1.100")
	session1.SetValid("user1", "", false, nil)

	session2 := mgr.CreateSession(SMB3_1_1, [16]byte{}, "192.168.1.101")
	session2.SetValid("user2", "", false, nil)

	// Wait for sessions to expire
	time.Sleep(150 * time.Millisecond)

	// Cleanup expired sessions
	expired := mgr.CleanupExpired()

	if len(expired) != 2 {
		t.Errorf("CleanupExpired() returned %d sessions, want 2", len(expired))
	}

	// Verify sessions were removed
	if mgr.GetSession(session1.ID) != nil {
		t.Error("Expired session1 still exists")
	}
	if mgr.GetSession(session2.ID) != nil {
		t.Error("Expired session2 still exists")
	}
}

// TestFileHandleMap_Allocate tests file handle allocation
func TestFileHandleMap_Allocate(t *testing.T) {
	m := NewFileHandleMap()
	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	file, err := fs.Create("/test.txt")
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	of := m.Allocate(file, "/test.txt", false, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN, 0, 1, 100)

	if of == nil {
		t.Fatal("Allocate() returned nil")
	}
	if of.ID.IsZero() {
		t.Error("FileID is zero")
	}
	if of.Path != "/test.txt" {
		t.Errorf("Path = %q, want \"/test.txt\"", of.Path)
	}
	if of.Access != FILE_READ_DATA {
		t.Errorf("Access = %x, want %x", of.Access, FILE_READ_DATA)
	}
	if of.TreeID != 1 {
		t.Errorf("TreeID = %d, want 1", of.TreeID)
	}
	if of.SessionID != 100 {
		t.Errorf("SessionID = %d, want 100", of.SessionID)
	}
}

// TestFileHandleMap_Get tests file handle retrieval
func TestFileHandleMap_Get(t *testing.T) {
	m := NewFileHandleMap()
	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	file, _ := fs.Create("/test.txt")
	of := m.Allocate(file, "/test.txt", false, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN, 0, 1, 100)

	t.Run("get existing handle", func(t *testing.T) {
		retrieved := m.Get(of.ID)
		if retrieved == nil {
			t.Fatal("Get() returned nil")
		}
		if retrieved.ID != of.ID {
			t.Errorf("FileID = %v, want %v", retrieved.ID, of.ID)
		}
	})

	t.Run("get non-existent handle", func(t *testing.T) {
		retrieved := m.Get(FileID{Persistent: 999, Volatile: 999})
		if retrieved != nil {
			t.Error("Get() for non-existent handle should return nil")
		}
	})
}

// TestFileHandleMap_Release tests file handle release
func TestFileHandleMap_Release(t *testing.T) {
	m := NewFileHandleMap()
	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	file, _ := fs.Create("/test.txt")
	of := m.Allocate(file, "/test.txt", false, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN, 0, 1, 100)

	err = m.Release(of.ID)
	if err != nil {
		t.Fatalf("Release() failed: %v", err)
	}

	// Verify handle was removed
	retrieved := m.Get(of.ID)
	if retrieved != nil {
		t.Error("Handle still exists after release")
	}
}

// TestFileHandleMap_ReleaseBySession tests releasing all handles for a session
func TestFileHandleMap_ReleaseBySession(t *testing.T) {
	m := NewFileHandleMap()
	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	// Allocate handles for different sessions
	file1, _ := fs.Create("/test1.txt")
	of1 := m.Allocate(file1, "/test1.txt", false, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN, 0, 1, 100)

	file2, _ := fs.Create("/test2.txt")
	of2 := m.Allocate(file2, "/test2.txt", false, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN, 0, 1, 100)

	file3, _ := fs.Create("/test3.txt")
	of3 := m.Allocate(file3, "/test3.txt", false, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN, 0, 1, 200)

	// Release all handles for session 100
	errors := m.ReleaseBySession(100)
	if len(errors) > 0 {
		t.Errorf("ReleaseBySession() returned errors: %v", errors)
	}

	// Verify session 100 handles were removed
	if m.Get(of1.ID) != nil {
		t.Error("Handle 1 still exists after ReleaseBySession")
	}
	if m.Get(of2.ID) != nil {
		t.Error("Handle 2 still exists after ReleaseBySession")
	}

	// Verify session 200 handle still exists
	if m.Get(of3.ID) == nil {
		t.Error("Handle 3 was incorrectly removed")
	}
}

// TestFileHandleMap_ReleaseByTree tests releasing all handles for a tree
func TestFileHandleMap_ReleaseByTree(t *testing.T) {
	m := NewFileHandleMap()
	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	// Allocate handles for different trees
	file1, _ := fs.Create("/test1.txt")
	of1 := m.Allocate(file1, "/test1.txt", false, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN, 0, 1, 100)

	file2, _ := fs.Create("/test2.txt")
	of2 := m.Allocate(file2, "/test2.txt", false, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN, 0, 2, 100)

	// Release all handles for tree 1, session 100
	errors := m.ReleaseByTree(1, 100)
	if len(errors) > 0 {
		t.Errorf("ReleaseByTree() returned errors: %v", errors)
	}

	// Verify tree 1 handle was removed
	if m.Get(of1.ID) != nil {
		t.Error("Handle 1 still exists after ReleaseByTree")
	}

	// Verify tree 2 handle still exists
	if m.Get(of2.ID) == nil {
		t.Error("Handle 2 was incorrectly removed")
	}
}

// TestFileHandleMap_CheckShareAccess tests share access compatibility checking
func TestFileHandleMap_CheckShareAccess(t *testing.T) {
	tests := []struct {
		name               string
		existingAccess     uint32
		existingShare      uint32
		newAccess          uint32
		newShare           uint32
		expectCompatible   bool
	}{
		{
			name:             "read with read share allowed",
			existingAccess:   FILE_READ_DATA,
			existingShare:    FILE_SHARE_READ,
			newAccess:        FILE_READ_DATA,
			newShare:         FILE_SHARE_READ,
			expectCompatible: true,
		},
		{
			name:             "read without read share denied",
			existingAccess:   FILE_READ_DATA,
			existingShare:    0,
			newAccess:        FILE_READ_DATA,
			newShare:         FILE_SHARE_READ,
			expectCompatible: false,
		},
		{
			name:             "write with write share allowed",
			existingAccess:   FILE_WRITE_DATA,
			existingShare:    FILE_SHARE_WRITE,
			newAccess:        FILE_WRITE_DATA,
			newShare:         FILE_SHARE_WRITE,
			expectCompatible: true,
		},
		{
			name:             "write without write share denied",
			existingAccess:   FILE_WRITE_DATA,
			existingShare:    0,
			newAccess:        FILE_WRITE_DATA,
			newShare:         FILE_SHARE_WRITE,
			expectCompatible: false,
		},
		{
			name:             "delete with delete share allowed",
			existingAccess:   DELETE,
			existingShare:    FILE_SHARE_DELETE,
			newAccess:        DELETE,
			newShare:         FILE_SHARE_DELETE,
			expectCompatible: true,
		},
		{
			name:             "delete without delete share denied",
			existingAccess:   DELETE,
			existingShare:    0,
			newAccess:        DELETE,
			newShare:         FILE_SHARE_DELETE,
			expectCompatible: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewFileHandleMap()
			fs, err := memfs.NewFS()
			if err != nil {
				t.Fatalf("Failed to create memfs: %v", err)
			}

			// Create existing handle
			file, _ := fs.Create("/test.txt")
			m.Allocate(file, "/test.txt", false, tt.existingAccess, tt.existingShare, FILE_OPEN, 0, 1, 100)

			// Check compatibility
			compatible := m.CheckShareAccess("/test.txt", tt.newAccess, tt.newShare)
			if compatible != tt.expectCompatible {
				t.Errorf("CheckShareAccess() = %v, want %v", compatible, tt.expectCompatible)
			}
		})
	}
}

// TestSMB2Header_Marshal tests SMB2 header marshaling
func TestSMB2Header_Marshal(t *testing.T) {
	header := &SMB2Header{
		StructureSize: SMB2HeaderSize,
		CreditCharge:  1,
		Status:        STATUS_SUCCESS,
		Command:       SMB2_NEGOTIATE,
		CreditRequest: 10,
		Flags:         SMB2_FLAGS_SERVER_TO_REDIR,
		NextCommand:   0,
		MessageID:     12345,
		Reserved:      0,
		TreeID:        0,
		SessionID:     67890,
	}
	copy(header.ProtocolID[:], SMB2ProtocolID)

	data := header.Marshal()

	if len(data) != SMB2HeaderSize {
		t.Errorf("Marshal() returned %d bytes, want %d", len(data), SMB2HeaderSize)
	}

	// Verify protocol ID
	if string(data[0:4]) != SMB2ProtocolID {
		t.Errorf("Protocol ID = %q, want %q", data[0:4], SMB2ProtocolID)
	}
}

// TestSMB2Header_Unmarshal tests SMB2 header unmarshaling
func TestSMB2Header_Unmarshal(t *testing.T) {
	original := &SMB2Header{
		StructureSize: SMB2HeaderSize,
		CreditCharge:  1,
		Status:        STATUS_SUCCESS,
		Command:       SMB2_NEGOTIATE,
		CreditRequest: 10,
		Flags:         SMB2_FLAGS_SERVER_TO_REDIR,
		NextCommand:   0,
		MessageID:     12345,
		Reserved:      0,
		TreeID:        0,
		SessionID:     67890,
	}
	copy(original.ProtocolID[:], SMB2ProtocolID)

	data := original.Marshal()
	parsed, err := UnmarshalSMB2Header(data)

	if err != nil {
		t.Fatalf("UnmarshalSMB2Header() failed: %v", err)
	}

	if parsed.StructureSize != original.StructureSize {
		t.Errorf("StructureSize = %d, want %d", parsed.StructureSize, original.StructureSize)
	}
	if parsed.Command != original.Command {
		t.Errorf("Command = %d, want %d", parsed.Command, original.Command)
	}
	if parsed.Status != original.Status {
		t.Errorf("Status = %v, want %v", parsed.Status, original.Status)
	}
	if parsed.MessageID != original.MessageID {
		t.Errorf("MessageID = %d, want %d", parsed.MessageID, original.MessageID)
	}
	if parsed.SessionID != original.SessionID {
		t.Errorf("SessionID = %d, want %d", parsed.SessionID, original.SessionID)
	}
}

// TestFileID_Marshal tests FileID marshaling
func TestFileID_Marshal(t *testing.T) {
	fid := FileID{
		Persistent: 0x123456789ABCDEF0,
		Volatile:   0xFEDCBA9876543210,
	}

	data := fid.Marshal()

	if len(data) != 16 {
		t.Errorf("Marshal() returned %d bytes, want 16", len(data))
	}

	// Unmarshal and verify
	parsed := UnmarshalFileID(data)
	if parsed.Persistent != fid.Persistent {
		t.Errorf("Persistent = %x, want %x", parsed.Persistent, fid.Persistent)
	}
	if parsed.Volatile != fid.Volatile {
		t.Errorf("Volatile = %x, want %x", parsed.Volatile, fid.Volatile)
	}
}

// TestFileID_IsZero tests FileID zero check
func TestFileID_IsZero(t *testing.T) {
	tests := []struct {
		name     string
		fid      FileID
		wantZero bool
	}{
		{
			name:     "zero FileID",
			fid:      FileID{Persistent: 0, Volatile: 0},
			wantZero: true,
		},
		{
			name:     "non-zero persistent",
			fid:      FileID{Persistent: 1, Volatile: 0},
			wantZero: false,
		},
		{
			name:     "non-zero volatile",
			fid:      FileID{Persistent: 0, Volatile: 1},
			wantZero: false,
		},
		{
			name:     "both non-zero",
			fid:      FileID{Persistent: 1, Volatile: 1},
			wantZero: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fid.IsZero(); got != tt.wantZero {
				t.Errorf("IsZero() = %v, want %v", got, tt.wantZero)
			}
		})
	}
}

// TestEncodeDecodeUTF16LE tests UTF-16LE string encoding/decoding
func TestEncodeDecodeUTF16LE(t *testing.T) {
	tests := []struct {
		name string
		str  string
	}{
		{"ASCII", "Hello World"},
		{"Unicode", "Hello 世界"},
		{"Empty", ""},
		{"Special chars", "test@#$%^&*()"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeStringToUTF16LE(tt.str)
			decoded := DecodeUTF16LEToString(encoded)

			if decoded != tt.str {
				t.Errorf("Decoded = %q, want %q", decoded, tt.str)
			}
		})
	}
}

// TestByteReader tests ByteReader operations
func TestByteReader(t *testing.T) {
	data := make([]byte, 32)
	le.PutUint16(data[0:2], 0x1234)
	le.PutUint32(data[2:6], 0x12345678)
	le.PutUint64(data[6:14], 0x123456789ABCDEF0)

	r := NewByteReader(data)

	t.Run("ReadUint16", func(t *testing.T) {
		v := r.ReadUint16()
		if v != 0x1234 {
			t.Errorf("ReadUint16() = %x, want 0x1234", v)
		}
	})

	t.Run("ReadUint32", func(t *testing.T) {
		v := r.ReadUint32()
		if v != 0x12345678 {
			t.Errorf("ReadUint32() = %x, want 0x12345678", v)
		}
	})

	t.Run("ReadUint64", func(t *testing.T) {
		v := r.ReadUint64()
		if v != 0x123456789ABCDEF0 {
			t.Errorf("ReadUint64() = %x, want 0x123456789ABCDEF0", v)
		}
	})

	t.Run("Position", func(t *testing.T) {
		pos := r.Position()
		if pos != 14 {
			t.Errorf("Position() = %d, want 14", pos)
		}
	})

	t.Run("Remaining", func(t *testing.T) {
		remaining := r.Remaining()
		if remaining != 18 {
			t.Errorf("Remaining() = %d, want 18", remaining)
		}
	})
}

// TestByteWriter tests ByteWriter operations
func TestByteWriter(t *testing.T) {
	w := NewByteWriter(32)

	t.Run("WriteUint16", func(t *testing.T) {
		w.WriteUint16(0x1234)
		if w.Len() != 2 {
			t.Errorf("Len() = %d, want 2", w.Len())
		}
	})

	t.Run("WriteUint32", func(t *testing.T) {
		w.WriteUint32(0x12345678)
		if w.Len() != 6 {
			t.Errorf("Len() = %d, want 6", w.Len())
		}
	})

	t.Run("WriteUint64", func(t *testing.T) {
		w.WriteUint64(0x123456789ABCDEF0)
		if w.Len() != 14 {
			t.Errorf("Len() = %d, want 14", w.Len())
		}
	})

	t.Run("Verify values", func(t *testing.T) {
		data := w.Bytes()
		r := NewByteReader(data)

		if v := r.ReadUint16(); v != 0x1234 {
			t.Errorf("Value = %x, want 0x1234", v)
		}
		if v := r.ReadUint32(); v != 0x12345678 {
			t.Errorf("Value = %x, want 0x12345678", v)
		}
		if v := r.ReadUint64(); v != 0x123456789ABCDEF0 {
			t.Errorf("Value = %x, want 0x123456789ABCDEF0", v)
		}
	})
}

// TestTimeToFiletime tests Windows FILETIME conversion
func TestTimeToFiletime(t *testing.T) {
	t.Run("zero time", func(t *testing.T) {
		ft := TimeToFiletime(time.Time{})
		if ft != 0 {
			t.Errorf("TimeToFiletime(zero) = %d, want 0", ft)
		}
	})

	t.Run("round trip", func(t *testing.T) {
		now := time.Now().UTC().Truncate(100 * time.Nanosecond)
		ft := TimeToFiletime(now)
		converted := FiletimeToTime(ft)

		diff := now.Sub(converted)
		if diff < 0 {
			diff = -diff
		}
		if diff > time.Microsecond {
			t.Errorf("Time conversion diff = %v, want < 1µs", diff)
		}
	})
}

// TestNTStatus_IsSuccess tests NT status success check
func TestNTStatus_IsSuccess(t *testing.T) {
	tests := []struct {
		status  NTStatus
		success bool
	}{
		{STATUS_SUCCESS, true},
		{STATUS_ACCESS_DENIED, false},
		{STATUS_NO_SUCH_FILE, false},
		{STATUS_PENDING, false},
	}

	for _, tt := range tests {
		t.Run(tt.status.String(), func(t *testing.T) {
			if got := tt.status.IsSuccess(); got != tt.success {
				t.Errorf("IsSuccess() = %v, want %v", got, tt.success)
			}
		})
	}
}

// TestNTStatus_IsError tests NT status error check
func TestNTStatus_IsError(t *testing.T) {
	tests := []struct {
		status NTStatus
		isErr  bool
	}{
		{STATUS_SUCCESS, false},
		{STATUS_PENDING, false},
		{STATUS_ACCESS_DENIED, true},
		{STATUS_NO_SUCH_FILE, true},
		{STATUS_INVALID_PARAMETER, true},
	}

	for _, tt := range tests {
		t.Run(tt.status.String(), func(t *testing.T) {
			if got := tt.status.IsError(); got != tt.isErr {
				t.Errorf("IsError() = %v, want %v", got, tt.isErr)
			}
		})
	}
}

// TestSMBDialect_String tests dialect string representation
func TestSMBDialect_String(t *testing.T) {
	tests := []struct {
		dialect SMBDialect
		want    string
	}{
		{SMB2_0_2, "SMB 2.0.2"},
		{SMB2_1, "SMB 2.1"},
		{SMB3_0, "SMB 3.0"},
		{SMB3_0_2, "SMB 3.0.2"},
		{SMB3_1_1, "SMB 3.1.1"},
		{SMBDialect(0x9999), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.dialect.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSession_SetValid tests session validation
func TestSession_SetValid(t *testing.T) {
	mgr := NewSessionManager(15 * time.Minute)
	session := mgr.CreateSession(SMB3_1_1, [16]byte{}, "192.168.1.100")

	session.SetValid("testuser", "TESTDOMAIN", false, []byte("signing-key"))

	if session.State != SessionStateValid {
		t.Errorf("State = %v, want SessionStateValid", session.State)
	}
	if session.Username != "testuser" {
		t.Errorf("Username = %q, want \"testuser\"", session.Username)
	}
	if session.Domain != "TESTDOMAIN" {
		t.Errorf("Domain = %q, want \"TESTDOMAIN\"", session.Domain)
	}
	if session.IsGuest {
		t.Error("IsGuest = true, want false")
	}
	if len(session.SigningKey) == 0 {
		t.Error("SigningKey is empty")
	}
}

// TestSession_TreeConnections tests tree connection management
func TestSession_TreeConnections(t *testing.T) {
	mgr := NewSessionManager(15 * time.Minute)
	session := mgr.CreateSession(SMB3_1_1, [16]byte{}, "192.168.1.100")
	session.SetValid("testuser", "", false, nil)

	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}
	share := NewShare(fs, ShareOptions{ShareName: "TestShare"})

	t.Run("add tree connection", func(t *testing.T) {
		tree := session.AddTreeConnection("TestShare", share, false)
		if tree == nil {
			t.Fatal("AddTreeConnection() returned nil")
		}
		if tree.ShareName != "TestShare" {
			t.Errorf("ShareName = %q, want \"TestShare\"", tree.ShareName)
		}
		if tree.Session != session {
			t.Error("Tree session does not match")
		}
	})

	t.Run("get tree connection", func(t *testing.T) {
		tree := session.AddTreeConnection("Share2", share, false)
		retrieved := session.GetTreeConnection(tree.ID)
		if retrieved == nil {
			t.Fatal("GetTreeConnection() returned nil")
		}
		if retrieved.ID != tree.ID {
			t.Errorf("TreeID = %d, want %d", retrieved.ID, tree.ID)
		}
	})

	t.Run("remove tree connection", func(t *testing.T) {
		tree := session.AddTreeConnection("Share3", share, false)
		removed := session.RemoveTreeConnection(tree.ID)
		if removed == nil {
			t.Fatal("RemoveTreeConnection() returned nil")
		}

		retrieved := session.GetTreeConnection(tree.ID)
		if retrieved != nil {
			t.Error("Tree still exists after removal")
		}
	})

	t.Run("tree count", func(t *testing.T) {
		count := session.TreeCount()
		if count < 1 {
			t.Errorf("TreeCount() = %d, want >= 1", count)
		}
	})
}

// TestShare_CheckUserAccess tests share user access checking
func TestShare_CheckUserAccess(t *testing.T) {
	tests := []struct {
		name          string
		shareOpts     ShareOptions
		username      string
		isGuest       bool
		expectAllowed bool
	}{
		{
			name:          "guest access allowed",
			shareOpts:     ShareOptions{AllowGuest: true},
			username:      "",
			isGuest:       true,
			expectAllowed: true,
		},
		{
			name:          "guest access denied",
			shareOpts:     ShareOptions{AllowGuest: false},
			username:      "",
			isGuest:       true,
			expectAllowed: false,
		},
		{
			name:          "authenticated user, no restrictions",
			shareOpts:     ShareOptions{AllowGuest: false, AllowedUsers: nil},
			username:      "testuser",
			isGuest:       false,
			expectAllowed: true,
		},
		{
			name:          "authenticated user in allowed list",
			shareOpts:     ShareOptions{AllowedUsers: []string{"user1", "user2"}},
			username:      "user1",
			isGuest:       false,
			expectAllowed: true,
		},
		{
			name:          "authenticated user not in allowed list",
			shareOpts:     ShareOptions{AllowedUsers: []string{"user1", "user2"}},
			username:      "user3",
			isGuest:       false,
			expectAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, err := memfs.NewFS()
			if err != nil {
				t.Fatalf("Failed to create memfs: %v", err)
			}
			share := NewShare(fs, tt.shareOpts)

			allowed := share.CheckUserAccess(tt.username, tt.isGuest)
			if allowed != tt.expectAllowed {
				t.Errorf("CheckUserAccess() = %v, want %v", allowed, tt.expectAllowed)
			}
		})
	}
}

// setupTestServer creates a test server with null logger
func setupTestServer(t *testing.T) *Server {
	t.Helper()

	opts := ServerOptions{
		Logger: &NullLogger{},
	}

	srv, err := NewServer(opts)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	return srv
}

// TestServer_ConnectionCount tests connection counting
func TestServer_ConnectionCount(t *testing.T) {
	srv := setupTestServer(t)

	count := srv.ConnectionCount()
	if count != 0 {
		t.Errorf("ConnectionCount() = %d, want 0", count)
	}
}

// TestServer_SessionCount tests session counting
func TestServer_SessionCount(t *testing.T) {
	srv := setupTestServer(t)

	count := srv.SessionCount()
	if count != 0 {
		t.Errorf("SessionCount() = %d, want 0", count)
	}

	// Add a session
	srv.sessions.CreateSession(SMB3_1_1, [16]byte{}, "192.168.1.100")

	count = srv.SessionCount()
	if count != 1 {
		t.Errorf("SessionCount() = %d, want 1", count)
	}
}

// TestGenerateMessageID tests message ID generation
func TestGenerateMessageID(t *testing.T) {
	ids := make(map[uint64]bool)

	// Generate multiple IDs and check for uniqueness
	for i := 0; i < 100; i++ {
		id := generateMessageID()
		if ids[id] {
			t.Errorf("Duplicate message ID: %d", id)
		}
		ids[id] = true
	}
}

// Benchmark tests

func BenchmarkSMB2Header_Marshal(b *testing.B) {
	header := &SMB2Header{
		StructureSize: SMB2HeaderSize,
		Command:       SMB2_NEGOTIATE,
		MessageID:     12345,
	}
	copy(header.ProtocolID[:], SMB2ProtocolID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = header.Marshal()
	}
}

func BenchmarkSMB2Header_Unmarshal(b *testing.B) {
	header := &SMB2Header{
		StructureSize: SMB2HeaderSize,
		Command:       SMB2_NEGOTIATE,
		MessageID:     12345,
	}
	copy(header.ProtocolID[:], SMB2ProtocolID)
	data := header.Marshal()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = UnmarshalSMB2Header(data)
	}
}

func BenchmarkEncodeStringToUTF16LE(b *testing.B) {
	str := "Hello World Test String"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncodeStringToUTF16LE(str)
	}
}

func BenchmarkDecodeUTF16LEToString(b *testing.B) {
	str := "Hello World Test String"
	data := EncodeStringToUTF16LE(str)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DecodeUTF16LEToString(data)
	}
}

func BenchmarkFileHandleMap_Allocate(b *testing.B) {
	m := NewFileHandleMap()
	fs, err := memfs.NewFS()
	if err != nil {
		b.Fatalf("Failed to create memfs: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		file, _ := fs.Create("/test.txt")
		_ = m.Allocate(file, "/test.txt", false, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN, 0, 1, 100)
	}
}

func BenchmarkSessionManager_CreateSession(b *testing.B) {
	mgr := NewSessionManager(15 * time.Minute)
	guid := [16]byte{}
	_, _ = rand.Read(guid[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mgr.CreateSession(SMB3_1_1, guid, "192.168.1.100")
	}
}

// =============================================================================
// Phase 2 tests
// =============================================================================

// --- Server Config ---

func TestDefaultServerOptions(t *testing.T) {
	opts := DefaultServerOptions()

	if opts.Port != 445 {
		t.Errorf("Port = %d, want 445", opts.Port)
	}
	if opts.MaxConnections != 100 {
		t.Errorf("MaxConnections = %d, want 100", opts.MaxConnections)
	}
	if opts.ReadTimeout != 30*time.Second {
		t.Errorf("ReadTimeout = %v, want 30s", opts.ReadTimeout)
	}
	if opts.WriteTimeout != 30*time.Second {
		t.Errorf("WriteTimeout = %v, want 30s", opts.WriteTimeout)
	}
	if opts.IdleTimeout != 15*time.Minute {
		t.Errorf("IdleTimeout = %v, want 15m", opts.IdleTimeout)
	}
	if opts.MinDialect != SMB2_0_2 {
		t.Errorf("MinDialect = %v, want SMB2_0_2", opts.MinDialect)
	}
	if opts.MaxDialect != SMB3_1_1 {
		t.Errorf("MaxDialect = %v, want SMB3_1_1", opts.MaxDialect)
	}
}

func TestDefaultShareOptions(t *testing.T) {
	opts := DefaultShareOptions("MyShare")

	if opts.ShareName != "MyShare" {
		t.Errorf("ShareName = %q, want %q", opts.ShareName, "MyShare")
	}
	if opts.ReadOnly {
		t.Error("ReadOnly = true, want false")
	}
	if opts.SharePath != "/" {
		t.Errorf("SharePath = %q, want %q", opts.SharePath, "/")
	}
}

func TestShareAccessors(t *testing.T) {
	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	opts := ShareOptions{
		ShareName:  "TestAcc",
		ReadOnly:   true,
		AllowGuest: true,
		ShareType:  SMBShareTypePipe,
	}
	share := NewShare(fs, opts)

	if share.FileSystem() == nil {
		t.Error("FileSystem() returned nil")
	}
	if share.Options().ShareName != "TestAcc" {
		t.Errorf("Options().ShareName = %q, want %q", share.Options().ShareName, "TestAcc")
	}
	if share.FileHandles() == nil {
		t.Error("FileHandles() returned nil")
	}
	if !share.IsReadOnly() {
		t.Error("IsReadOnly() = false, want true")
	}
	if share.GetShareType() != SMBShareTypePipe {
		t.Errorf("GetShareType() = %v, want SMBShareTypePipe", share.GetShareType())
	}
	if !share.AllowsGuest() {
		t.Error("AllowsGuest() = false, want true")
	}

	// Verify default share type when zero
	share2 := NewShare(fs, ShareOptions{ShareName: "Default"})
	if share2.GetShareType() != SMBShareTypeDisk {
		t.Errorf("GetShareType() default = %v, want SMBShareTypeDisk", share2.GetShareType())
	}
}

func TestShareValidateCredentials(t *testing.T) {
	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	t.Run("with users", func(t *testing.T) {
		share := NewShare(fs, ShareOptions{
			ShareName: "AuthShare",
			Users:     map[string]string{"alice": "pass123", "bob": "secret"},
		})

		if !share.ValidateCredentials("alice", "pass123") {
			t.Error("correct creds should return true")
		}
		if share.ValidateCredentials("alice", "wrong") {
			t.Error("wrong password should return false")
		}
		if share.ValidateCredentials("unknown", "pass123") {
			t.Error("unknown user should return false")
		}
	})

	t.Run("without users", func(t *testing.T) {
		share := NewShare(fs, ShareOptions{ShareName: "NoAuth"})

		if !share.ValidateCredentials("anyone", "anything") {
			t.Error("no users configured should always return true")
		}
	})
}

func TestDefaultLogger(t *testing.T) {
	logger := NewDefaultLogger(true)

	// Just verify no panic; the methods write to the standard log which we
	// don't capture here but the important thing is they don't crash.
	logger.Debug("debug %s", "msg")
	logger.Info("info %s", "msg")
	logger.Warn("warn %s", "msg")
	logger.Error("error %s", "msg")

	// With debug disabled
	loggerNonDebug := NewDefaultLogger(false)
	loggerNonDebug.Debug("should be suppressed %s", "msg")
	loggerNonDebug.Info("info %s", "msg")
}

func TestNullLoggerMethods(t *testing.T) {
	logger := &NullLogger{}

	// All methods must be callable without panic
	logger.Debug("debug %s", "msg")
	logger.Info("info %s", "msg")
	logger.Warn("warn %s", "msg")
	logger.Error("error %s", "msg")
}

func TestServerAccessors(t *testing.T) {
	srv := setupTestServer(t)

	if srv.Options().Port != 445 {
		t.Errorf("Options().Port = %d, want 445", srv.Options().Port)
	}
	if srv.Sessions() == nil {
		t.Error("Sessions() returned nil")
	}
	if srv.Logger() == nil {
		t.Error("Logger() returned nil")
	}
}

// --- Session Manager gaps ---

func TestSessionManager_GetSessionByGUID(t *testing.T) {
	mgr := NewSessionManager(15 * time.Minute)

	guid := [16]byte{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160}
	session := mgr.CreateSession(SMB3_1_1, guid, "10.0.0.1")

	t.Run("hit", func(t *testing.T) {
		found := mgr.GetSessionByGUID(guid)
		if found == nil {
			t.Fatal("GetSessionByGUID() returned nil")
		}
		if found.ID != session.ID {
			t.Errorf("session ID = %d, want %d", found.ID, session.ID)
		}
	})

	t.Run("miss", func(t *testing.T) {
		wrongGUID := [16]byte{0xFF, 0xFF}
		found := mgr.GetSessionByGUID(wrongGUID)
		if found != nil {
			t.Error("GetSessionByGUID() with wrong GUID should return nil")
		}
	})
}

func TestSessionManager_UpdateActivity(t *testing.T) {
	mgr := NewSessionManager(15 * time.Minute)
	session := mgr.CreateSession(SMB3_1_1, [16]byte{}, "10.0.0.1")

	before := session.LastActivity
	time.Sleep(5 * time.Millisecond)
	mgr.UpdateActivity(session.ID)

	session.mu.RLock()
	after := session.LastActivity
	session.mu.RUnlock()

	if !after.After(before) {
		t.Errorf("LastActivity was not updated: before=%v, after=%v", before, after)
	}
}

func TestSession_GetAllTreeConnections(t *testing.T) {
	mgr := NewSessionManager(15 * time.Minute)
	session := mgr.CreateSession(SMB3_1_1, [16]byte{}, "10.0.0.1")
	session.SetValid("user", "", false, nil)

	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}
	share := NewShare(fs, ShareOptions{ShareName: "S"})

	session.AddTreeConnection("S1", share, false)
	session.AddTreeConnection("S2", share, false)
	session.AddTreeConnection("S3", share, false)

	trees := session.GetAllTreeConnections()
	if len(trees) != 3 {
		t.Errorf("GetAllTreeConnections() returned %d, want 3", len(trees))
	}
}

func TestSession_ValidateTreeConnection(t *testing.T) {
	mgr := NewSessionManager(15 * time.Minute)
	session := mgr.CreateSession(SMB3_1_1, [16]byte{}, "10.0.0.1")
	session.SetValid("user", "", false, nil)

	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}
	share := NewShare(fs, ShareOptions{ShareName: "VS"})
	tree := session.AddTreeConnection("VS", share, false)

	t.Run("valid tree", func(t *testing.T) {
		found, status := session.ValidateTreeConnection(tree.ID)
		if status != STATUS_SUCCESS {
			t.Errorf("status = %v, want STATUS_SUCCESS", status)
		}
		if found == nil || found.ID != tree.ID {
			t.Error("returned wrong tree connection")
		}
	})

	t.Run("invalid tree ID", func(t *testing.T) {
		_, status := session.ValidateTreeConnection(0xDEAD)
		if status != STATUS_NETWORK_NAME_DELETED {
			t.Errorf("status = %v, want STATUS_NETWORK_NAME_DELETED", status)
		}
	})
}

// --- FileHandleMap gaps ---

func TestFileHandleMap_GetBySession(t *testing.T) {
	m := NewFileHandleMap()
	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	file, _ := fs.Create("/sess.txt")
	of := m.Allocate(file, "/sess.txt", false, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN, 0, 1, 100)

	t.Run("matching session", func(t *testing.T) {
		got := m.GetBySession(of.ID, 100)
		if got == nil {
			t.Fatal("GetBySession() returned nil for correct session")
		}
		if got.ID != of.ID {
			t.Errorf("ID mismatch: got %v, want %v", got.ID, of.ID)
		}
	})

	t.Run("wrong session", func(t *testing.T) {
		got := m.GetBySession(of.ID, 999)
		if got != nil {
			t.Error("GetBySession() should return nil for wrong session")
		}
	})
}

func TestFileHandleMap_GetByTree(t *testing.T) {
	m := NewFileHandleMap()
	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	file, _ := fs.Create("/tree.txt")
	of := m.Allocate(file, "/tree.txt", false, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN, 0, 5, 200)

	t.Run("matching tree and session", func(t *testing.T) {
		got := m.GetByTree(of.ID, 5, 200)
		if got == nil {
			t.Fatal("GetByTree() returned nil for correct tree+session")
		}
	})

	t.Run("wrong tree", func(t *testing.T) {
		got := m.GetByTree(of.ID, 99, 200)
		if got != nil {
			t.Error("GetByTree() should return nil for wrong tree")
		}
	})

	t.Run("wrong session", func(t *testing.T) {
		got := m.GetByTree(of.ID, 5, 999)
		if got != nil {
			t.Error("GetByTree() should return nil for wrong session")
		}
	})
}

func TestFileHandleMap_Count(t *testing.T) {
	m := NewFileHandleMap()
	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	if m.Count() != 0 {
		t.Errorf("empty map Count() = %d, want 0", m.Count())
	}

	var ids [3]FileID
	for i := 0; i < 3; i++ {
		f, _ := fs.Create(fmt.Sprintf("/count%d.txt", i))
		of := m.Allocate(f, fmt.Sprintf("/count%d.txt", i), false, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN, 0, 1, 100)
		ids[i] = of.ID
	}

	if m.Count() != 3 {
		t.Errorf("after 3 allocations Count() = %d, want 3", m.Count())
	}

	_ = m.Release(ids[0])

	if m.Count() != 2 {
		t.Errorf("after 1 release Count() = %d, want 2", m.Count())
	}
}

func TestFileHandleMap_GetOpenHandlesForPath(t *testing.T) {
	m := NewFileHandleMap()
	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	f1, _ := fs.Create("/shared.txt")
	f2, _ := fs.Create("/shared.txt")
	m.Allocate(f1, "/shared.txt", false, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN, 0, 1, 100)
	m.Allocate(f2, "/shared.txt", false, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN, 0, 1, 200)

	handles := m.GetOpenHandlesForPath("/shared.txt")
	if len(handles) != 2 {
		t.Errorf("GetOpenHandlesForPath() returned %d handles, want 2", len(handles))
	}

	// Different path should return none
	handles = m.GetOpenHandlesForPath("/other.txt")
	if len(handles) != 0 {
		t.Errorf("GetOpenHandlesForPath(/other.txt) returned %d handles, want 0", len(handles))
	}
}

func TestFileHandleMap_UpdateLastAccess(t *testing.T) {
	m := NewFileHandleMap()
	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	file, _ := fs.Create("/access.txt")
	of := m.Allocate(file, "/access.txt", false, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN, 0, 1, 100)

	before := of.LastAccess
	time.Sleep(5 * time.Millisecond)
	m.UpdateLastAccess(of.ID)

	updated := m.Get(of.ID)
	if !updated.LastAccess.After(before) {
		t.Errorf("LastAccess was not updated: before=%v, after=%v", before, updated.LastAccess)
	}
}

func TestFileHandleMap_DeleteOnClose(t *testing.T) {
	m := NewFileHandleMap()
	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	file, _ := fs.Create("/del.txt")
	of := m.Allocate(file, "/del.txt", false, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN, 0, 1, 100)

	// Initially false
	if m.GetDeleteOnClose(of.ID) {
		t.Error("GetDeleteOnClose() = true, want false initially")
	}

	m.SetDeleteOnClose(of.ID, true)
	if !m.GetDeleteOnClose(of.ID) {
		t.Error("GetDeleteOnClose() = false after SetDeleteOnClose(true)")
	}

	m.SetDeleteOnClose(of.ID, false)
	if m.GetDeleteOnClose(of.ID) {
		t.Error("GetDeleteOnClose() = true after SetDeleteOnClose(false)")
	}
}

// --- Guest Auth ---

func TestGuestAuthenticator(t *testing.T) {
	auth := NewGuestAuthenticator()
	if auth == nil {
		t.Fatal("NewGuestAuthenticator() returned nil")
	}

	result, err := auth.Authenticate([]byte("any blob"))
	if err != nil {
		t.Fatalf("Authenticate() error: %v", err)
	}
	if !result.Success {
		t.Error("Success = false, want true")
	}
	if !result.IsGuest {
		t.Error("IsGuest = false, want true")
	}
	if result.Username != "Guest" {
		t.Errorf("Username = %q, want %q", result.Username, "Guest")
	}

	// Also try with empty blob
	result2, err := auth.Authenticate(nil)
	if err != nil {
		t.Fatalf("Authenticate(nil) error: %v", err)
	}
	if !result2.Success {
		t.Error("Authenticate(nil) Success = false, want true")
	}
}
