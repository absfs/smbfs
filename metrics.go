package smbfs

import (
	"sync"
	"sync/atomic"
	"time"
)

// MetricsCollector collects operation metrics for the SMB server
type MetricsCollector struct {
	enabled bool

	// Operation counters
	ops map[string]*opMetrics

	// Connection metrics
	totalConnections   atomic.Int64
	activeConnections  atomic.Int64
	rejectedConnections atomic.Int64

	// Session metrics
	totalSessions  atomic.Int64
	activeSessions atomic.Int64

	// Error metrics
	totalErrors atomic.Int64
	authFailures atomic.Int64

	// Rate limit metrics
	rateLimited atomic.Int64

	// Byte counters
	bytesRead    atomic.Int64
	bytesWritten atomic.Int64

	// Latency tracking
	mu              sync.Mutex
	latencyBuckets  map[string]*latencyTracker

	// Start time
	startTime time.Time
}

// opMetrics tracks per-operation metrics
type opMetrics struct {
	count    atomic.Int64
	errors   atomic.Int64
	duration atomic.Int64 // nanoseconds total
}

// latencyTracker tracks latency distribution for an operation
type latencyTracker struct {
	count    int64
	totalNs  int64
	minNs    int64
	maxNs    int64
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(enabled bool) *MetricsCollector {
	mc := &MetricsCollector{
		enabled:        enabled,
		ops:            make(map[string]*opMetrics),
		latencyBuckets: make(map[string]*latencyTracker),
		startTime:      time.Now(),
	}

	// Pre-register known operations
	for _, op := range []string{
		"NEGOTIATE", "SESSION_SETUP", "LOGOFF",
		"TREE_CONNECT", "TREE_DISCONNECT",
		"CREATE", "CLOSE", "READ", "WRITE", "FLUSH",
		"LOCK", "IOCTL", "CANCEL", "ECHO",
		"QUERY_DIRECTORY", "CHANGE_NOTIFY",
		"QUERY_INFO", "SET_INFO", "OPLOCK_BREAK",
	} {
		mc.ops[op] = &opMetrics{}
	}

	return mc
}

// RecordOp records a completed operation
func (mc *MetricsCollector) RecordOp(op string, duration time.Duration, err bool) {
	if !mc.enabled {
		return
	}
	m, ok := mc.ops[op]
	if !ok {
		mc.mu.Lock()
		m = &opMetrics{}
		mc.ops[op] = m
		mc.mu.Unlock()
	}
	m.count.Add(1)
	m.duration.Add(int64(duration))
	if err {
		m.errors.Add(1)
		mc.totalErrors.Add(1)
	}

	// Track latency
	mc.mu.Lock()
	lt, ok := mc.latencyBuckets[op]
	if !ok {
		lt = &latencyTracker{minNs: int64(duration)}
		mc.latencyBuckets[op] = lt
	}
	lt.count++
	lt.totalNs += int64(duration)
	if int64(duration) < lt.minNs {
		lt.minNs = int64(duration)
	}
	if int64(duration) > lt.maxNs {
		lt.maxNs = int64(duration)
	}
	mc.mu.Unlock()
}

// RecordConnection records a new connection
func (mc *MetricsCollector) RecordConnection() {
	if !mc.enabled {
		return
	}
	mc.totalConnections.Add(1)
	mc.activeConnections.Add(1)
}

// RecordDisconnection records a disconnection
func (mc *MetricsCollector) RecordDisconnection() {
	if !mc.enabled {
		return
	}
	mc.activeConnections.Add(-1)
}

// RecordRejectedConnection records a rejected connection
func (mc *MetricsCollector) RecordRejectedConnection() {
	if !mc.enabled {
		return
	}
	mc.rejectedConnections.Add(1)
}

// RecordSession records a new session
func (mc *MetricsCollector) RecordSession() {
	if !mc.enabled {
		return
	}
	mc.totalSessions.Add(1)
	mc.activeSessions.Add(1)
}

// RecordSessionEnd records a session ending
func (mc *MetricsCollector) RecordSessionEnd() {
	if !mc.enabled {
		return
	}
	mc.activeSessions.Add(-1)
}

// RecordAuthFailure records an authentication failure
func (mc *MetricsCollector) RecordAuthFailure() {
	if !mc.enabled {
		return
	}
	mc.authFailures.Add(1)
}

// RecordRateLimited records a rate-limited request
func (mc *MetricsCollector) RecordRateLimited() {
	if !mc.enabled {
		return
	}
	mc.rateLimited.Add(1)
}

// RecordBytesRead records bytes read
func (mc *MetricsCollector) RecordBytesRead(n int64) {
	if !mc.enabled {
		return
	}
	mc.bytesRead.Add(n)
}

// RecordBytesWritten records bytes written
func (mc *MetricsCollector) RecordBytesWritten(n int64) {
	if !mc.enabled {
		return
	}
	mc.bytesWritten.Add(n)
}

// Snapshot returns a point-in-time snapshot of all metrics
func (mc *MetricsCollector) Snapshot() ServerMetrics {
	sm := ServerMetrics{
		Uptime:              time.Since(mc.startTime),
		TotalConnections:    mc.totalConnections.Load(),
		ActiveConnections:   mc.activeConnections.Load(),
		RejectedConnections: mc.rejectedConnections.Load(),
		TotalSessions:       mc.totalSessions.Load(),
		ActiveSessions:      mc.activeSessions.Load(),
		TotalErrors:         mc.totalErrors.Load(),
		AuthFailures:        mc.authFailures.Load(),
		RateLimited:         mc.rateLimited.Load(),
		BytesRead:           mc.bytesRead.Load(),
		BytesWritten:        mc.bytesWritten.Load(),
		Operations:          make(map[string]OpMetrics),
	}

	for name, m := range mc.ops {
		count := m.count.Load()
		if count == 0 {
			continue
		}
		totalDuration := m.duration.Load()
		om := OpMetrics{
			Count:       count,
			Errors:      m.errors.Load(),
			TotalTimeNs: totalDuration,
			AvgTimeNs:   totalDuration / count,
		}

		mc.mu.Lock()
		if lt, ok := mc.latencyBuckets[name]; ok {
			om.MinTimeNs = lt.minNs
			om.MaxTimeNs = lt.maxNs
		}
		mc.mu.Unlock()

		sm.Operations[name] = om
	}

	return sm
}

// ServerMetrics is a point-in-time snapshot of server metrics
type ServerMetrics struct {
	Uptime              time.Duration
	TotalConnections    int64
	ActiveConnections   int64
	RejectedConnections int64
	TotalSessions       int64
	ActiveSessions      int64
	TotalErrors         int64
	AuthFailures        int64
	RateLimited         int64
	BytesRead           int64
	BytesWritten        int64
	Operations          map[string]OpMetrics
}

// OpMetrics contains metrics for a single operation type
type OpMetrics struct {
	Count       int64
	Errors      int64
	TotalTimeNs int64
	AvgTimeNs   int64
	MinTimeNs   int64
	MaxTimeNs   int64
}
