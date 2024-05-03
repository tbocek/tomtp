package tomtp

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

// helper function to create a new SndSegment with minimal required data
func newSndSegment[T any](sn uint32, data T) *SndSegment[T] {
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

	assert.Equal(t, uint32(10), ring.Capacity())
	assert.Equal(t, uint32(5), ring.Limit())
}

// TestInsertSequence tests inserting both sequential and non-sequential
// segments into the ring buffer, expecting specific statuses in return
// (SndInserted for sequential inserts and SndNotASequence for a
// non-sequential insert).
func TestInsertSequence(t *testing.T) {
	ring := NewRingBufferSnd[int](10, 10)

	// Insert sequential segments
	for i := uint32(0); i < 5; i++ {
		status := ring.Insert(newSndSegment[int](i, int(i)))
		assert.Equal(t, SndInserted, status)
	}

	// Insert a non-sequential segment
	status := ring.Insert(newSndSegment[int](10, 10))
	assert.Equal(t, SndNotASequence, status)
}

// TestOverflowHandling tests the buffer's behavior when attempting to insert
// more segments than its capacity allows, expecting an SndOverflow status.
func TestOverflowHandling(t *testing.T) {
	ring := NewRingBufferSnd[int](3, 3)

	// Fill the buffer to its limit
	for i := uint32(0); i < 3; i++ {
		ring.Insert(newSndSegment[int](i, int(i)))
	}

	// Try inserting one more
	status := ring.Insert(newSndSegment[int](3, 3))
	assert.Equal(t, SndOverflow, status)
}

// TestRemovalAndOrder tests the removal of segments from the buffer,
// ensuring that the removal is processed correctly and the buffer's
// order and size are updated accordingly.
func TestRemovalAndOrder(t *testing.T) {
	ring := NewRingBufferSnd[int](10, 10)
	ring.Insert(newSndSegment[int](0, 0))
	ring.Insert(newSndSegment[int](1, 1))

	removedSegment := ring.Remove(0)
	assert.NotNil(t, removedSegment)
	assert.Equal(t, uint32(0), removedSegment.sn)
	assert.Equal(t, uint32(1), ring.Size())
}

// TestLimitAdjustment tests adjusting the limit of the buffer and
// expects a specific behavior (potentially a panic) when setting
// the limit below the current size.
func TestLimitAdjustment(t *testing.T) {
	ring := NewRingBufferSnd[int](5, 5)
	for i := uint32(0); i < 5; i++ {
		ring.Insert(newSndSegment[int](i, int(i)))
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
	for i := uint32(0); i < 5; i++ {
		status := ring.Insert(newSndSegment[int](i, int(i)))
		assert.Equal(t, SndInserted, status)
	}

	// Increase the limit
	ring.SetLimit(10)

	// Insert more items up to the new limit
	for i := uint32(5); i < 10; i++ {
		status := ring.Insert(newSndSegment[int](i, int(i)))
		assert.Equal(t, SndInserted, status)
	}

	// Check if the size is as expected after limit increase
	expectedSize := uint32(10)
	if ring.Size() != expectedSize {
		t.Errorf("Expected size to be %d after increasing limit, got %d", expectedSize, ring.Size())
	}
}

// TestDecreaseLimitSnd1 tests the RingBufferSnd's response to reaching its limit.
// After initializing the buffer and filling it to half capacity, it sets the limit
// to match the current fill level, confirming no further inserts are allowed by
// expecting an SndOverflow error. It then checks that existing segments can be
// removed in the correct order, ensuring the buffer manages its limit and maintains
// order integrity after operations.
func TestDecreaseLimitSnd1(t *testing.T) {
	// Initialize RingBufferSnd with initial limit lower than capacity
	ring := NewRingBufferSnd[int](10, 10)

	// Fill up to initial limit
	for i := uint32(0); i < 5; i++ {
		status := ring.Insert(newSndSegment[int](i, int(i)))
		assert.Equal(t, SndInserted, status)
	}

	// Increase the limit
	ring.SetLimit(5)

	segment := newSndSegment(uint32(5), 0)
	inserted := ring.Insert(segment)
	assert.Equal(t, inserted, SndOverflow)
	assert.Equal(t, uint32(5), ring.size)

	for i := uint32(0); i < 5; i++ {
		segment := ring.Remove(i)
		assert.Equal(t, uint32(i), segment.sn)
	}
}

// TestDecreaseLimitSnd2 checks how RingBufferSnd handles a decrease in its limit
// below its current fill level. After populating the buffer to half its capacity,
// it reduces the limit to below the number of items inserted, testing if additional
// inserts are correctly blocked by an SndOverflow error. It also tests sequential
// removals, verifying the buffer's size decreases accordingly and maintains data order.
func TestDecreaseLimitSnd2(t *testing.T) {
	// Initialize RingBufferSnd with initial limit lower than capacity
	ring := NewRingBufferSnd[int](10, 10)

	// Fill up to initial limit
	for i := uint32(0); i < 5; i++ {
		status := ring.Insert(newSndSegment[int](i, int(i)))
		assert.Equal(t, SndInserted, status)
	}

	// Increase the limit
	ring.SetLimit(4)

	segment := newSndSegment(uint32(5), 0)
	inserted := ring.Insert(segment)
	assert.Equal(t, inserted, SndOverflow)
	assert.Equal(t, uint32(5), ring.size)

	for i := uint32(0); i < 5; i++ {
		segment := ring.Remove(i)
		assert.Equal(t, uint32(4-i), ring.size)
		assert.Equal(t, uint32(i), segment.sn)
	}
}

func TestReschedule(t *testing.T) {
	// Create a new ring buffer with capacity for 5 segments and a current limit of 5
	ring := NewRingBufferSnd[int](5, 5)

	// Define current time in milliseconds and a timeout
	nowMillis := time.Now().UnixMilli()
	timeout := int64(10000) // 10 seconds

	// Insert segments with varying sentMillis to test timeout behavior
	ring.Insert(&SndSegment[int]{sn: 0, sentMillis: nowMillis - 15000, data: 100}) // Should timeout
	ring.Insert(&SndSegment[int]{sn: 1, sentMillis: nowMillis - 5000, data: 200})  // Should not timeout
	ring.Insert(&SndSegment[int]{sn: 2, sentMillis: nowMillis - 20000, data: 300}) // Should timeout

	// Call Reschedule to find and update segments that timed out
	result := ring.ReadyToSend(timeout, nowMillis)

	// Check the results
	assert.Equal(t, 2, len(result), "Expected 2 segments to be rescheduled")

	// Verify that the correct segments were returned and updated
	assert.Equal(t, nowMillis, result[0].sentMillis, "Expected sentMillis to be updated to current time")
	assert.Equal(t, 100, result[0].data, "Expected sentMillis to be updated to current time")
	assert.Equal(t, nowMillis, result[1].sentMillis, "Expected sentMillis to be updated to current time")
	assert.Equal(t, 300, result[1].data, "Expected sentMillis to be updated to current time")
}

func TestInsertBlockingIncreaseLimit(t *testing.T) {
	// Create a new ring buffer with capacity for 3 segments
	ring := NewRingBufferSnd[int](3, 4)

	// Fill the buffer to capacity
	for i := 0; i < 3; i++ {
		ring.Insert(&SndSegment[int]{sn: uint32(i), sentMillis: int64(i * 1000), data: i})
	}

	// Use a channel to signal when the insertion has completed
	done := make(chan bool)

	go func() {
		// This should block since the buffer is full
		status := ring.InsertBlocking(&SndSegment[int]{sn: 3, sentMillis: 3000, data: 300})
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
	for i := 0; i < 3; i++ {
		ring.Insert(&SndSegment[int]{sn: uint32(i), sentMillis: int64(i * 1000), data: i})
	}

	// Use a channel to signal when the insertion has completed
	done := make(chan bool)

	go func() {
		// This should block since the buffer is full
		status := ring.InsertBlocking(&SndSegment[int]{sn: 3, sentMillis: 3000, data: 300})
		assert.Equal(t, SndInserted, status, "Expected segment to be inserted after blocking")
		done <- true
	}()

	// Wait a bit then increase the buffer limit to simulate space availability
	go func() {
		time.Sleep(100 * time.Millisecond) // Simulate delay
		ring.Remove(0)
	}()

	select {
	case <-done:
		// Success, test should pass
	case <-time.After(1 * time.Second):
		// Test should fail if blocking does not resolve in reasonable time
		t.Error("Timed out waiting for InsertBlocking to complete")
	}
}
