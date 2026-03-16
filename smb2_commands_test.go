package smbfs

import (
	"fmt"
	"testing"
)

func TestCommandName(t *testing.T) {
	tests := []struct {
		cmd  uint16
		want string
	}{
		{SMB2_NEGOTIATE, "NEGOTIATE"},
		{SMB2_SESSION_SETUP, "SESSION_SETUP"},
		{SMB2_LOGOFF, "LOGOFF"},
		{SMB2_TREE_CONNECT, "TREE_CONNECT"},
		{SMB2_TREE_DISCONNECT, "TREE_DISCONNECT"},
		{SMB2_CREATE, "CREATE"},
		{SMB2_CLOSE, "CLOSE"},
		{SMB2_FLUSH, "FLUSH"},
		{SMB2_READ, "READ"},
		{SMB2_WRITE, "WRITE"},
		{SMB2_LOCK, "LOCK"},
		{SMB2_IOCTL, "IOCTL"},
		{SMB2_CANCEL, "CANCEL"},
		{SMB2_ECHO, "ECHO"},
		{SMB2_QUERY_DIRECTORY, "QUERY_DIRECTORY"},
		{SMB2_CHANGE_NOTIFY, "CHANGE_NOTIFY"},
		{SMB2_QUERY_INFO, "QUERY_INFO"},
		{SMB2_SET_INFO, "SET_INFO"},
		{SMB2_OPLOCK_BREAK, "OPLOCK_BREAK"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := CommandName(tt.cmd)
			if got != tt.want {
				t.Errorf("CommandName(0x%04X) = %q, want %q", tt.cmd, got, tt.want)
			}
		})
	}

	t.Run("unknown command", func(t *testing.T) {
		got := CommandName(0xFFFF)
		if got != "UNKNOWN" {
			t.Errorf("CommandName(0xFFFF) = %q, want %q", got, "UNKNOWN")
		}
	})

	t.Run(fmt.Sprintf("Unknown(0x%04X)", SMB2_OPLOCK_BREAK+1), func(t *testing.T) {
		got := CommandName(SMB2_OPLOCK_BREAK + 1)
		if got != "UNKNOWN" {
			t.Errorf("CommandName(0x%04X) = %q, want %q", SMB2_OPLOCK_BREAK+1, got, "UNKNOWN")
		}
	})
}

func TestIsValidCommand(t *testing.T) {
	t.Run("all valid commands", func(t *testing.T) {
		validCmds := []uint16{
			SMB2_NEGOTIATE, SMB2_SESSION_SETUP, SMB2_LOGOFF,
			SMB2_TREE_CONNECT, SMB2_TREE_DISCONNECT,
			SMB2_CREATE, SMB2_CLOSE, SMB2_FLUSH,
			SMB2_READ, SMB2_WRITE, SMB2_LOCK,
			SMB2_IOCTL, SMB2_CANCEL, SMB2_ECHO,
			SMB2_QUERY_DIRECTORY, SMB2_CHANGE_NOTIFY,
			SMB2_QUERY_INFO, SMB2_SET_INFO, SMB2_OPLOCK_BREAK,
		}
		for _, cmd := range validCmds {
			if !IsValidCommand(cmd) {
				t.Errorf("IsValidCommand(0x%04X) = false, want true", cmd)
			}
		}
	})

	t.Run("one past max is invalid", func(t *testing.T) {
		cmd := SMB2_OPLOCK_BREAK + 1
		if IsValidCommand(cmd) {
			t.Errorf("IsValidCommand(0x%04X) = true, want false", cmd)
		}
	})

	t.Run("0xFFFF is invalid", func(t *testing.T) {
		if IsValidCommand(0xFFFF) {
			t.Error("IsValidCommand(0xFFFF) = true, want false")
		}
	})
}
