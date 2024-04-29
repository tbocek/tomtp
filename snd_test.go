package tomtp

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/rand"
	"testing"
)

// helper function to create a new SndSegment with minimal required data
func newSndSegment[T any](sn uint32, data T) *SndSegment[T] {
	return &SndSegment[T]{
		sn:      sn,
		tMillis: timeMilli(),
		data:    data,
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

	for i := 0; i < 5; i++ {
		segment := ring.Remove(uint32(i))
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

	for i := 0; i < 5; i++ {
		segment := ring.Remove(uint32(i))
		assert.Equal(t, uint32(4-i), ring.size)
		assert.Equal(t, uint32(i), segment.sn)
	}
}

// TestDecreaseLimitSnd3 evaluates RingBufferSnd for correct behavior when its
// limit is reduced and then tested against insertions and reverse order removals.
// It fills the buffer to a certain point, lowers the limit below this level, and
// confirms that no more insertions are possible, indicating proper limit enforcement.
// The test further assesses the buffer's handling of data and limit integrity by
// removing items in reverse order, checking that each removal accurately reflects
// the expected size and limit.
func TestDecreaseLimitSnd3(t *testing.T) {
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

	for i := 4; i >= 0; i-- {
		segment := ring.Remove(uint32(i))
		assert.Equal(t, uint32(4), ring.currentLimit)
		assert.Equal(t, uint32(i), ring.size)
		assert.Equal(t, uint32(i), segment.sn)
	}
}

// TestOldest tests identifying the oldest segment in the buffer and ensuring
// that the buffer updates correctly when the oldest segment is removed.
func TestOldest(t *testing.T) {
	ring := NewRingBufferSnd[int](10, 10)

	for i := 0; i < 5; i++ {
		seg := newSndSegment(uint32(i), i) // Assuming makeSegment creates a segment with identifiable data.
		inserted := ring.Insert(seg)
		require.Equal(t, inserted, SndInserted)
	}

	oldest := ring.PeekOldest()
	assert.Equal(t, uint32(0), oldest.sn)
	ring.Remove(uint32(0))
	oldest = ring.PeekOldest()
	assert.Equal(t, uint32(1), oldest.sn)
	ring.Remove(uint32(5))
	oldest = ring.PeekOldest()
	assert.Equal(t, uint32(1), oldest.sn)
}

// TestFuzz is a fuzz test that performs a large number of random insertions and
// removals to stress-test the buffer's handling of dynamic changes.
func TestFuzz(t *testing.T) {
	ring := NewRingBufferSnd[int](10, 10)

	seqIns := 0
	seqRem := 0
	rand := rand.New(rand.NewSource(42))

	for j := 0; j < 100000; j++ {
		rnd := rand.Intn(10) + 1

		for i := 0; i < rnd; i++ {
			seg := newSndSegment(uint32(seqIns), 0)

			inserted := ring.Insert(seg)
			if inserted != SndInserted {
				rnd = i + 1
				break
			} else {
				seqIns++
			}
		}

		rnd2 := rand.Intn(rnd) + 1
		if rand.Intn(2) == 0 {
			rnd2 = rand.Intn(seqIns-seqRem) + 1
		}

		for i := 0; i < rnd2; i++ {
			ring.Remove(uint32(seqRem))
			seqRem++
		}

	}
	assert.Equal(t, 369127, seqIns)
	assert.Equal(t, 369124, seqRem)
}
