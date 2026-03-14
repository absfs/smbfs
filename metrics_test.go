package smbfs

import (
	"testing"
	"time"
)

func TestMetricsCollector_Disabled(t *testing.T) {
	mc := NewMetricsCollector(false)

	// Should not panic when disabled
	mc.RecordOp("READ", time.Millisecond, false)
	mc.RecordConnection()
	mc.RecordDisconnection()
	mc.RecordBytesRead(100)
	mc.RecordBytesWritten(200)
	mc.RecordAuthFailure()
	mc.RecordRateLimited()

	snap := mc.Snapshot()
	if snap.TotalConnections != 0 {
		t.Error("expected no connections when disabled")
	}
}

func TestMetricsCollector_Operations(t *testing.T) {
	mc := NewMetricsCollector(true)

	mc.RecordOp("READ", 5*time.Millisecond, false)
	mc.RecordOp("READ", 10*time.Millisecond, false)
	mc.RecordOp("READ", 15*time.Millisecond, true)
	mc.RecordOp("WRITE", 3*time.Millisecond, false)

	snap := mc.Snapshot()

	readOps, ok := snap.Operations["READ"]
	if !ok {
		t.Fatal("expected READ operations")
	}
	if readOps.Count != 3 {
		t.Errorf("expected 3 READ ops, got %d", readOps.Count)
	}
	if readOps.Errors != 1 {
		t.Errorf("expected 1 READ error, got %d", readOps.Errors)
	}

	writeOps, ok := snap.Operations["WRITE"]
	if !ok {
		t.Fatal("expected WRITE operations")
	}
	if writeOps.Count != 1 {
		t.Errorf("expected 1 WRITE op, got %d", writeOps.Count)
	}
}

func TestMetricsCollector_Connections(t *testing.T) {
	mc := NewMetricsCollector(true)

	mc.RecordConnection()
	mc.RecordConnection()
	mc.RecordConnection()
	mc.RecordDisconnection()
	mc.RecordRejectedConnection()

	snap := mc.Snapshot()
	if snap.TotalConnections != 3 {
		t.Errorf("expected 3 total connections, got %d", snap.TotalConnections)
	}
	if snap.ActiveConnections != 2 {
		t.Errorf("expected 2 active connections, got %d", snap.ActiveConnections)
	}
	if snap.RejectedConnections != 1 {
		t.Errorf("expected 1 rejected connection, got %d", snap.RejectedConnections)
	}
}

func TestMetricsCollector_ByteCounters(t *testing.T) {
	mc := NewMetricsCollector(true)

	mc.RecordBytesRead(100)
	mc.RecordBytesRead(200)
	mc.RecordBytesWritten(500)

	snap := mc.Snapshot()
	if snap.BytesRead != 300 {
		t.Errorf("expected 300 bytes read, got %d", snap.BytesRead)
	}
	if snap.BytesWritten != 500 {
		t.Errorf("expected 500 bytes written, got %d", snap.BytesWritten)
	}
}

func TestMetricsCollector_Sessions(t *testing.T) {
	mc := NewMetricsCollector(true)

	mc.RecordSession()
	mc.RecordSession()
	mc.RecordSessionEnd()

	snap := mc.Snapshot()
	if snap.TotalSessions != 2 {
		t.Errorf("expected 2 total sessions, got %d", snap.TotalSessions)
	}
	if snap.ActiveSessions != 1 {
		t.Errorf("expected 1 active session, got %d", snap.ActiveSessions)
	}
}

func TestMetricsCollector_AuthFailures(t *testing.T) {
	mc := NewMetricsCollector(true)

	mc.RecordAuthFailure()
	mc.RecordAuthFailure()
	mc.RecordAuthFailure()

	snap := mc.Snapshot()
	if snap.AuthFailures != 3 {
		t.Errorf("expected 3 auth failures, got %d", snap.AuthFailures)
	}
}

func TestMetricsCollector_Latency(t *testing.T) {
	mc := NewMetricsCollector(true)

	mc.RecordOp("READ", 1*time.Millisecond, false)
	mc.RecordOp("READ", 5*time.Millisecond, false)
	mc.RecordOp("READ", 10*time.Millisecond, false)

	snap := mc.Snapshot()
	readOps := snap.Operations["READ"]

	if readOps.MinTimeNs > int64(2*time.Millisecond) {
		t.Errorf("expected min time <= 2ms, got %d ns", readOps.MinTimeNs)
	}
	if readOps.MaxTimeNs < int64(9*time.Millisecond) {
		t.Errorf("expected max time >= 9ms, got %d ns", readOps.MaxTimeNs)
	}
}

func TestMetricsCollector_Uptime(t *testing.T) {
	mc := NewMetricsCollector(true)

	snap := mc.Snapshot()
	if snap.Uptime <= 0 {
		t.Error("expected positive uptime")
	}
}
