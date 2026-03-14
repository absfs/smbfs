package smbfs

import (
	"sync"
	"sync/atomic"
)

// WorkerPoolConfig configures the worker pool
type WorkerPoolConfig struct {
	// Enabled enables the worker pool for bounded concurrency
	Enabled bool

	// Size is the number of worker goroutines
	Size int

	// QueueSize is the maximum number of queued tasks
	QueueSize int
}

// DefaultWorkerPoolConfig returns sensible defaults
func DefaultWorkerPoolConfig() WorkerPoolConfig {
	return WorkerPoolConfig{
		Enabled:   false,
		Size:      64,
		QueueSize: 1024,
	}
}

// WorkerPool provides bounded concurrency for request processing
type WorkerPool struct {
	config  WorkerPoolConfig
	tasks   chan workerTask
	wg      sync.WaitGroup
	stopped atomic.Bool

	// Stats
	submitted atomic.Int64
	completed atomic.Int64
	rejected  atomic.Int64
}

// workerTask wraps a function to execute and a channel for the result
type workerTask struct {
	fn     func()
	done   chan struct{}
}

// NewWorkerPool creates and starts a new worker pool
func NewWorkerPool(config WorkerPoolConfig) *WorkerPool {
	if config.Size <= 0 {
		config.Size = 64
	}
	if config.QueueSize <= 0 {
		config.QueueSize = 1024
	}

	wp := &WorkerPool{
		config: config,
		tasks:  make(chan workerTask, config.QueueSize),
	}

	if config.Enabled {
		wp.start()
	}

	return wp
}

// start launches worker goroutines
func (wp *WorkerPool) start() {
	for i := 0; i < wp.config.Size; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}
}

// worker processes tasks from the queue
func (wp *WorkerPool) worker() {
	defer wp.wg.Done()
	for task := range wp.tasks {
		task.fn()
		wp.completed.Add(1)
		if task.done != nil {
			close(task.done)
		}
	}
}

// Submit submits a task to the worker pool.
// If the pool is not enabled, the task is executed immediately.
// Returns false if the task was rejected (queue full).
func (wp *WorkerPool) Submit(fn func()) bool {
	if !wp.config.Enabled || wp.stopped.Load() {
		// Execute inline if pool is disabled
		fn()
		return true
	}

	wp.submitted.Add(1)

	select {
	case wp.tasks <- workerTask{fn: fn}:
		return true
	default:
		// Queue is full
		wp.rejected.Add(1)
		return false
	}
}

// SubmitWait submits a task and waits for it to complete.
// If the pool is not enabled, the task is executed immediately.
func (wp *WorkerPool) SubmitWait(fn func()) bool {
	if !wp.config.Enabled || wp.stopped.Load() {
		fn()
		return true
	}

	wp.submitted.Add(1)
	done := make(chan struct{})

	select {
	case wp.tasks <- workerTask{fn: fn, done: done}:
		<-done
		return true
	default:
		wp.rejected.Add(1)
		return false
	}
}

// Stop shuts down the worker pool and waits for all workers to finish
func (wp *WorkerPool) Stop() {
	if !wp.config.Enabled || wp.stopped.Swap(true) {
		return
	}
	close(wp.tasks)
	wp.wg.Wait()
}

// Resize changes the number of workers in the pool.
// New workers are added or existing workers are allowed to drain.
func (wp *WorkerPool) Resize(newSize int) {
	if !wp.config.Enabled || newSize <= 0 {
		return
	}

	currentSize := wp.config.Size
	if newSize > currentSize {
		// Add more workers
		for i := 0; i < newSize-currentSize; i++ {
			wp.wg.Add(1)
			go wp.worker()
		}
	}
	// For shrinking, we let excess workers drain naturally when the pool stops
	wp.config.Size = newSize
}

// Stats returns worker pool statistics
func (wp *WorkerPool) Stats() WorkerPoolStats {
	return WorkerPoolStats{
		Enabled:    wp.config.Enabled,
		PoolSize:   wp.config.Size,
		QueueSize:  wp.config.QueueSize,
		QueueUsed:  len(wp.tasks),
		Submitted:  wp.submitted.Load(),
		Completed:  wp.completed.Load(),
		Rejected:   wp.rejected.Load(),
	}
}

// WorkerPoolStats provides statistics about the worker pool
type WorkerPoolStats struct {
	Enabled   bool
	PoolSize  int
	QueueSize int
	QueueUsed int
	Submitted int64
	Completed int64
	Rejected  int64
}
