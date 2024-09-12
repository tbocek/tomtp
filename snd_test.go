package tomtp

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

// helper function to create a new SndSegment with minimal required data
func newSndSegment[T any](sn uint64, data T) *SndSegment[T] {
	return &SndSegment[T]{
		sn:   sn,
		data: data,
	}
}

// TestNewRingBufferSnd tests the creation of a new RingBufferSnd with
// specified limit and capacity, and verifies that these
// properties are set correctly.
func TestNewRingBufferSnd(t *testing.T) {
	ring := NewRingBufferSnd[int](5, 10)

	assert.Equal(t, uint64(10), ring.Capacity())
	assert.Equal(t, uint64(5), ring.Limit())
	assert.Equal(t, uint64(1), ring.minSn)
	assert.Equal(t, uint64(1), ring.maxSn)
}

// TestInsertSequence tests inserting both sequential
// segments into the ring buffer, expecting specific statuses in return
// (SndInserted for sequential inserts).
func TestInsertSequence(t *testing.T) {
	ring := NewRingBufferSnd[int](10, 10)

	// Insert sequential segments
	for i := uint64(1); i <= 5; i++ {
		sn, status := ring.Insert(int(i))
		assert.Equal(t, SndInserted, status)
		assert.Equal(t, i, sn)
	}
}

// TestOverflowHandling tests the buffer's behavior when attempting to insert
// more segments than its capacity allows, expecting an SndOverflow status.
func TestOverflowHandling(t *testing.T) {
	ring := NewRingBufferSnd[int](3, 3)

	// Fill the buffer to its limit
	for i := uint32(1); i <= 3; i++ {
		ring.Insert(int(i))
	}

	// Try inserting one more
	_, status := ring.Insert(int(4))
	assert.Equal(t, SndOverflow, status)
}

// TestRemovalAndOrder tests the removal of segments from the buffer,
// ensuring that the removal is processed correctly and the buffer's
// order and size are updated accordingly.
func TestRemovalAndOrder(t *testing.T) {
	ring := NewRingBufferSnd[int](10, 10)
	ring.Insert(1)
	ring.Insert(2)

	removedSegment := ring.Remove(1)
	assert.NotNil(t, removedSegment)
	assert.Equal(t, uint64(1), removedSegment.sn)
	assert.Equal(t, uint64(1), ring.Size())
}

// TestLimitAdjustment tests adjusting the limit of the buffer and
// expects a specific behavior (potentially a panic) when setting
// the limit below the current size.
func TestLimitAdjustment(t *testing.T) {
	ring := NewRingBufferSnd[int](5, 5)
	for i := uint32(1); i <= 5; i++ {
		ring.Insert(int(i))
	}

	// Decrease limit below current size
	defer func() {
		assert.NotNil(t, recover())
	}()
	ring.SetLimit(10)
}

// TestIncreaseLimitSnd is similar to TestLimitAdjustment, but focuses on
// increasing the limit and testing the buffer's behavior under these conditions.
func TestIncreaseLimitSnd(t *testing.T) {
	// Initialize RingBufferSnd with initial limit lower than capacity
	ring := NewRingBufferSnd[int](5, 10)

	// Fill up to initial limit
	for i := uint64(1); i <= 5; i++ {
		_, status := ring.Insert(int(i))
		assert.Equal(t, SndInserted, status)
	}

	// Increase the limit
	ring.SetLimit(10)

	// Insert more items up to the new limit
	for i := uint64(6); i <= 10; i++ {
		_, status := ring.Insert(int(i))
		assert.Equal(t, SndInserted, status)
	}

	// Check if the size is as expected after limit increase
	expectedSize := uint64(10)
	assert.Equal(t, expectedSize, ring.Size())
}

// TestDecreaseLimitSnd1 tests the RingBufferSnd's response to reaching its limit.
func TestDecreaseLimitSnd1(t *testing.T) {
	// Initialize RingBufferSnd with initial limit lower than capacity
	ring := NewRingBufferSnd[int](10, 10)

	// Fill up to initial limit
	for i := uint64(1); i <= 5; i++ {
		_, status := ring.Insert(int(i))
		assert.Equal(t, SndInserted, status)
	}

	// Decrease the limit
	ring.SetLimit(5)

	_, inserted := ring.Insert(6)
	assert.Equal(t, SndOverflow, inserted)
	assert.Equal(t, uint64(5), ring.size)

	for i := uint64(1); i <= 5; i++ {
		segment := ring.Remove(i)
		assert.Equal(t, i, segment.sn)
	}
}

// TestDecreaseLimitSnd2 checks how RingBufferSnd handles a decrease in its limit
// below its current fill level.
func TestDecreaseLimitSnd2(t *testing.T) {
	// Initialize RingBufferSnd with initial limit lower than capacity
	ring := NewRingBufferSnd[int](10, 10)

	// Fill up to initial limit
	for i := uint64(1); i <= 5; i++ {
		_, status := ring.Insert(int(i))
		assert.Equal(t, SndInserted, status)
	}

	// Decrease the limit
	ring.SetLimit(4)

	_, inserted := ring.Insert(6)
	assert.Equal(t, SndOverflow, inserted)
	assert.Equal(t, uint64(5), ring.size)

	for i := uint64(1); i <= 5; i++ {
		segment := ring.Remove(i)
		assert.Equal(t, uint64(5-i), ring.size)
		assert.Equal(t, i, segment.sn)
	}
}

func TestInsertBlockingIncreaseLimit(t *testing.T) {
	// Create a new ring buffer with capacity for 3 segments
	ring := NewRingBufferSnd[int](3, 4)

	// Fill the buffer to capacity
	for i := 1; i <= 3; i++ {
		ring.Insert(i)
	}

	// Use a channel to signal when the insertion has completed
	done := make(chan bool)

	go func() {
		// This should block since the buffer is full
		_, status := ring.InsertBlocking(300)
		assert.Equal(t, SndInserted, status, "Expected segment to be inserted after blocking")
		done <- true
	}()

	// Wait a bit then increase the buffer limit to simulate space availability
	go func() {
		time.Sleep(100 * time.Millisecond) // Simulate delay
		ring.SetLimit(4)
	}()

	select {
	case <-done:
		// Success, test should pass
	case <-time.After(1 * time.Second):
		// Test should fail if blocking does not resolve in reasonable time
		t.Error("Timed out waiting for InsertBlocking to complete")
	}
}

func TestInsertBlockingRemove(t *testing.T) {
	// Create a new ring buffer with capacity for 3 segments
	ring := NewRingBufferSnd[int](3, 4)

	// Fill the buffer to capacity
	for i := 1; i <= 3; i++ {
		ring.Insert(i)
	}

	// Use a channel to signal when the insertion has completed
	done := make(chan bool)

	go func() {
		// This should block since the buffer is full
		_, status := ring.InsertBlocking(300)
		assert.Equal(t, SndInserted, status, "Expected segment to be inserted after blocking")
		done <- true
	}()

	// Wait a bit then increase the buffer limit to simulate space availability
	go func() {
		time.Sleep(100 * time.Millisecond) // Simulate delay
		ring.Remove(1)
	}()

	select {
	case <-done:
		// Success, test should pass
	case <-time.After(1 * time.Second):
		// Test should fail if blocking does not resolve in reasonable time
		t.Error("Timed out waiting for InsertBlocking to complete")
	}
}

// Helper function to create a RingBufferSnd with some pre-filled segments
func createRingBufferSndWithSegments[T any](limit, capacity uint64, segments []*SndSegment[T]) *RingBufferSnd[T] {
	ring := NewRingBufferSnd[T](limit, capacity)
	for _, segment := range segments {
		ring.Insert(segment.data)
	}
	return ring
}

func TestInvalidSequenceNumber(t *testing.T) {
	ring := NewRingBufferSnd[int](5, 5)

	// Attempt to remove segment with sequence number 0
	removedSegment := ring.Remove(0)
	assert.Nil(t, removedSegment, "Expected nil when removing segment with sequence number 0")
}
