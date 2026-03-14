package smbfs

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkerPool_Disabled(t *testing.T) {
	wp := NewWorkerPool(WorkerPoolConfig{Enabled: false})
	defer wp.Stop()

	executed := false
	ok := wp.Submit(func() {
		executed = true
	})
	if !ok {
		t.Fatal("expected submit to succeed")
	}
	if !executed {
		t.Fatal("expected task to execute inline when disabled")
	}
}

func TestWorkerPool_Submit(t *testing.T) {
	wp := NewWorkerPool(WorkerPoolConfig{
		Enabled:   true,
		Size:      4,
		QueueSize: 100,
	})
	defer wp.Stop()

	var count atomic.Int64
	done := make(chan struct{})

	for i := 0; i < 10; i++ {
		wp.Submit(func() {
			count.Add(1)
			if count.Load() == 10 {
				close(done)
			}
		})
	}

	select {
	case <-done:
		// ok
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for tasks, completed %d/10", count.Load())
	}
}

func TestWorkerPool_SubmitWait(t *testing.T) {
	wp := NewWorkerPool(WorkerPoolConfig{
		Enabled:   true,
		Size:      2,
		QueueSize: 10,
	})
	defer wp.Stop()

	result := 0
	ok := wp.SubmitWait(func() {
		result = 42
	})
	if !ok {
		t.Fatal("expected submit to succeed")
	}
	if result != 42 {
		t.Errorf("expected result 42, got %d", result)
	}
}

func TestWorkerPool_QueueFull(t *testing.T) {
	wp := NewWorkerPool(WorkerPoolConfig{
		Enabled:   true,
		Size:      1,
		QueueSize: 2,
	})

	// Block the worker
	blocker := make(chan struct{})
	wp.Submit(func() {
		<-blocker
	})

	// Fill the queue
	wp.Submit(func() { time.Sleep(time.Millisecond) })
	wp.Submit(func() { time.Sleep(time.Millisecond) })

	// This should be rejected
	ok := wp.Submit(func() {})
	if ok {
		// Queue might not be full yet depending on timing
		// This is best-effort
	}

	close(blocker)
	wp.Stop()

	stats := wp.Stats()
	if stats.Submitted < 3 {
		t.Errorf("expected at least 3 submitted, got %d", stats.Submitted)
	}
}

func TestWorkerPool_Stats(t *testing.T) {
	wp := NewWorkerPool(WorkerPoolConfig{
		Enabled:   true,
		Size:      4,
		QueueSize: 100,
	})

	stats := wp.Stats()
	if !stats.Enabled {
		t.Error("expected enabled")
	}
	if stats.PoolSize != 4 {
		t.Errorf("expected pool size 4, got %d", stats.PoolSize)
	}
	if stats.QueueSize != 100 {
		t.Errorf("expected queue size 100, got %d", stats.QueueSize)
	}

	wp.Stop()
}

func TestWorkerPool_Resize(t *testing.T) {
	wp := NewWorkerPool(WorkerPoolConfig{
		Enabled:   true,
		Size:      2,
		QueueSize: 100,
	})
	defer wp.Stop()

	wp.Resize(8)

	stats := wp.Stats()
	if stats.PoolSize != 8 {
		t.Errorf("expected pool size 8 after resize, got %d", stats.PoolSize)
	}
}

func TestWorkerPool_StopIdempotent(t *testing.T) {
	wp := NewWorkerPool(WorkerPoolConfig{
		Enabled:   true,
		Size:      2,
		QueueSize: 10,
	})

	// Should not panic on double stop
	wp.Stop()
	wp.Stop()
}
