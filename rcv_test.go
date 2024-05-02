package tomtp

import (
	"github.com/stretchr/testify/assert"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// helper function to create a new RcvSegment with minimal required data
func newRcvSegment[T any](sn uint32, data T) *RcvSegment[T] {
	return &RcvSegment[T]{
		sn:   sn,
		data: data,
	}
}

// TestFull verifies that the ring buffer correctly handles being filled to its capacity.
// It inserts segments up to the buffer's limit and checks that the last insert operation
// correctly reports an overflow error, indicating that the buffer is full.
func TestFull(t *testing.T) {
	ring := NewRingBufferRcv[int](10, 10)

	for i := 0; i < 10; i++ {
		segment := newRcvSegment(uint32(i), 0)
		inserted := ring.Insert(segment)
		assert.Equal(t, RcvInserted, inserted)
	}

	segment := newRcvSegment(uint32(10), 0)
	inserted := ring.Insert(segment)
	assert.Equal(t, RcvOverflow, inserted)
}

// TestInsertTwice checks that inserting a segment with a duplicate sequence number
// is correctly identified and rejected as a duplicate.
func TestInsertTwice(t *testing.T) {
	ring := NewRingBufferRcv[int](10, 10)
	segment := newRcvSegment(uint32(1), 0)
	inserted := ring.Insert(segment)
	assert.Equal(t, inserted, RcvInserted)
	segment = newRcvSegment(uint32(1), 0)
	inserted = ring.Insert(segment)
	assert.Equal(t, inserted, RcvDuplicate)
}

// TestInsertToLarge verifies that the buffer correctly handles an attempt to insert
// a segment that is outside of its current range, resulting in an overflow error.
func TestInsertToLarge(t *testing.T) {
	ring := NewRingBufferRcv[int](10, 10)
	segment := newRcvSegment(uint32(0), 0)
	inserted := ring.Insert(segment)
	assert.Equal(t, inserted, RcvInserted)
	segment = newRcvSegment(uint32(10), 0)
	inserted = ring.Insert(segment)
	assert.Equal(t, inserted, RcvOverflow)
}

// TestInsertOutOfOrder checks the behavior when removing segments from an empty buffer
// and verifies that the buffer size is updated correctly after an insert operation.
func TestInsertOutOfOrder(t *testing.T) {
	ring := NewRingBufferRcv[int](10, 10)
	segment := newRcvSegment(uint32(1), 0)
	inserted := ring.Insert(segment)
	assert.Equal(t, inserted, RcvInserted)

	s := ring.Remove()
	assert.Nil(t, s)
	assert.Equal(t, uint32(1), ring.size)
}

// TestInsertOutOfOrder2 verifies that the ring buffer can correctly handle insertion of segments in a non-sequential order.
// It tests the scenario where a segment with a higher sequence number is inserted before a segment with a lower sequence number.
// The test ensures that both segments are successfully inserted into the buffer and can be removed in the correct order.
// Additionally, it checks that attempting to remove more segments than have been inserted results in a nil response,
// indicating that the buffer is empty. This tests the ring buffer's ability to manage out-of-order data while maintaining
// the integrity and order of the data.
func TestInsertOutOfOrder2(t *testing.T) {
	ring := NewRingBufferRcv[int](10, 10)
	segment := newRcvSegment(uint32(1), 0)
	inserted := ring.Insert(segment)
	assert.Equal(t, inserted, RcvInserted)

	segment = newRcvSegment(uint32(0), 0)
	inserted = ring.Insert(segment)
	assert.Equal(t, inserted, RcvInserted)

	s1 := ring.Remove()
	s2 := ring.Remove()
	s3 := ring.Remove()
	assert.NotNil(t, s1)
	assert.NotNil(t, s2)
	assert.Nil(t, s3)
}

// TestInsertBackwards checks the ring buffer's behavior when segments are inserted in reverse order,
// starting from a high sequence number down to the lowest one. This test is crucial for verifying
// the buffer's ability to correctly handle segments arriving in completely reverse sequence order.
// It aims to ensure that the ring buffer can still organize and store the segments properly
// even when they arrive backwards. After inserting all segments in reverse order, the test attempts
// to remove a segment before the final, lowest-sequence segment is inserted, expecting no segment
// to be removable yet, illustrating the buffer's handling of missing sequence numbers. Finally,
// it verifies that once all segments are inserted, they can be sequentially removed, demonstrating
// the buffer's capability to reorder and correctly manage out-of-sequence data insertions.
func TestInsertBackwards(t *testing.T) {
	ring := NewRingBufferRcv[int](10, 10)
	for i := 0; i < 9; i++ {
		seg := newRcvSegment(uint32(9-i), 0)
		inserted := ring.Insert(seg)
		assert.Equal(t, inserted, RcvInserted)
	}
	s := ring.Remove()
	assert.Nil(t, s)

	seg := newRcvSegment(uint32(0), 0)
	inserted := ring.Insert(seg)
	assert.Equal(t, inserted, RcvInserted)

	i := removeUntilNil(ring)
	assert.Equal(t, 10, i)
}

// TestModulo verifies the ring buffer's handling of sequence number wrapping.
// This scenario is essential for ensuring the buffer correctly processes cases
// where the sequence numbers exceed the buffer's maximum value and wrap around.
// Initially, segments are inserted up to the buffer's capacity, then removed to test
// the buffer's ability to reset and accept new segments as if starting fresh.
// The test demonstrates the buffer's capability to manage continuous data flow across
// the theoretical limits of sequence numbers by validating insertions and removals
// before and after the sequence number wrap.
func TestModulo(t *testing.T) {
	ring := NewRingBufferRcv[int](10, 10)

	for i := 0; i < 10; i++ {
		segment := newRcvSegment(uint32(i), 0)
		inserted := ring.Insert(segment)
		assert.Equal(t, inserted, RcvInserted)
	}

	i := removeUntilNil(ring)
	assert.Equal(t, 10, i)

	for i := 10; i < 20; i++ {
		segment := newRcvSegment(uint32(i), 0)
		inserted := ring.Insert(segment)
		assert.Equal(t, inserted, RcvInserted)
	}

	i = removeUntilNil(ring)
	assert.Equal(t, 10, i)
	assert.Equal(t, uint32(0), ring.size)
}

// TestIncreaseLimit examines the ring buffer's behavior when its limit is increased.
// It's crucial for ensuring the buffer can dynamically adjust to accommodate more segments
// without losing existing data. The test first fills the buffer up to its initial limit,
// then increases the limit and continues to insert segments, checking that these new
// inserts are successful. This confirms the buffer's capability to adapt to changing
// requirements and maintain integrity and order of the data, even as its capacity is modified.
func TestIncreaseLimit(t *testing.T) {
	ring := NewRingBufferRcv[int](5, 10)

	for i := 0; i < 5; i++ {
		segment := newRcvSegment(uint32(i), 0)
		inserted := ring.Insert(segment)
		assert.Equal(t, inserted, RcvInserted)
	}

	ring.SetLimit(10)

	for i := 5; i < 10; i++ {
		segment := newRcvSegment(uint32(i), 0)
		inserted := ring.Insert(segment)
		assert.Equal(t, inserted, RcvInserted)
	}

	assert.Equal(t, uint32(10), ring.size)
}

// TestDecreaseLimit1 evaluates the ring buffer's functionality when its limit is decreased.
// This scenario tests the buffer's ability to handle a reduction in its capacity without
// compromising the integrity of the data already inserted. Initially, the buffer is filled
// partially, followed by a decrease in its limit. The test then verifies that subsequent insertions
// that exceed the new limit are correctly rejected as overflows. It also checks that the existing
// segments within the new limit remain accessible and in order, ensuring the buffer's adaptability
// to shrinking capacities while maintaining data consistency.
func TestDecreaseLimit1(t *testing.T) {
	ring := NewRingBufferRcv[int](10, 10)

	for i := 0; i < 5; i++ {
		segment := newRcvSegment(uint32(i), 0)
		inserted := ring.Insert(segment)
		assert.Equal(t, inserted, RcvInserted)
	}

	ring.SetLimit(5)
	assert.Equal(t, uint32(5), ring.currentLimit)

	segment := newRcvSegment(uint32(5), 0)
	inserted := ring.Insert(segment)
	assert.Equal(t, inserted, RcvOverflow)
	assert.Equal(t, uint32(5), ring.size)

	for i := 0; i < 5; i++ {
		segment := ring.Remove()
		assert.Equal(t, uint32(i), segment.sn)
	}
}

// TestDecreaseLimit2 assesses the ring buffer's response to a
// decrease in limit that does not take effect due to current usage
// exceeding the new limit. It ensures that the buffer maintains
// its current limit when an attempt to decrease it below the number
// of segments already in the buffer is made. This test inserts
// segments up to half the buffer's capacity, tries to set a new
// limit lower than the current content, and verifies that the
// buffer correctly refuses to decrease its limit, protecting
// the integrity of the data. It then checks if further insertions
// are correctly reported as overflows and confirms the removal of
// existing segments respects the unchanged limit.
func TestDecreaseLimit2(t *testing.T) {
	ring := NewRingBufferRcv[int](10, 10)

	for i := 0; i < 5; i++ {
		segment := newRcvSegment(uint32(i), 0)
		inserted := ring.Insert(segment)
		assert.Equal(t, inserted, RcvInserted)
	}

	ring.SetLimit(4)
	assert.Equal(t, uint32(5), ring.currentLimit)

	segment := newRcvSegment(uint32(5), 0)
	inserted := ring.Insert(segment)
	assert.Equal(t, inserted, RcvOverflow)
	assert.Equal(t, uint32(5), ring.size)

	for i := 0; i < 5; i++ {
		segment := ring.Remove()
		assert.Equal(t, uint32(4), ring.currentLimit)
		assert.Equal(t, uint32(i), segment.sn)
	}
}

// TestDuplicateSN checks the ring buffer's ability to detect and reject
// duplicate sequence numbers. This test is vital for ensuring data integrity,
// preventing the buffer from accepting multiple segments with the same sequence
// number. The procedure involves inserting a segment, verifying its successful
// insertion, then attempting to insert another segment with the same sequence
// number and expecting it to be identified as a duplicate.
func TestDuplicateSN(t *testing.T) {
	ring := NewRingBufferRcv[int](10, 10)
	segment := newRcvSegment(uint32(1), 0)
	inserted := ring.Insert(segment)
	assert.Equal(t, inserted, RcvInserted)
	segment = newRcvSegment(uint32(2), 0)
	inserted = ring.Insert(segment)
	assert.Equal(t, inserted, RcvInserted)
	inserted = ring.Insert(segment)
	assert.Equal(t, inserted, RcvDuplicate)
}

// TestParallel assesses the ring buffer's concurrency capabilities by
// performing parallel insertions. It's crucial for validating the buffer's
// thread-safety and its ability to handle simultaneous data operations
// without data loss or corruption. This test launches multiple goroutines,
// each performing insertions of segments into the buffer, simulating a
// high-concurrency environment. The goal is to ensure that the buffer
// can accurately manage concurrent access, correctly insert all segments
// without duplicates or losses, and maintain the integrity of the data.
func TestParallel(t *testing.T) {
	ring := NewRingBufferRcv[int](20, 20)

	mutex := sync.WaitGroup{}
	mutex.Add(3)

	go func() {
		for i := uint32(0); i <= uint32(9); i++ {
			if i < uint32(5) {
				seg := newRcvSegment(i, 0)
				status := ring.Insert(seg)
				assert.Equal(t, RcvInserted, status)
			}
		}
		mutex.Done()
	}()
	go func() {
		for i := uint32(10); i <= uint32(19); i++ {
			seg := newRcvSegment(i, 0)
			status := ring.Insert(seg)
			assert.Equal(t, RcvInserted, status)
		}
		mutex.Done()
	}()
	go func() {
		for i := uint32(0); i <= uint32(9); i++ {
			if i >= uint32(5) {
				seg := newRcvSegment(i, 0)
				status := ring.Insert(seg)
				assert.Equal(t, RcvInserted, status)
			}
		}
		mutex.Done()
	}()

	mutex.Wait()

	assert.Equal(t, uint32(20), ring.size)
	for {
		seg := ring.Remove()
		if seg == nil {
			break
		}
	}
	assert.Equal(t, uint32(0), ring.size)

}

// TestFuzz2 performs fuzz testing on the ring buffer to evaluate its
// robustness under random and intensive operations. This test generates
// a large number of insertions with random sequence numbers to
// simulate unpredictable workload patterns. It aims to stress-test
// the buffer's capacity to handle a wide range of sequence numbers
// and insertion rates without losing data integrity. By verifying that
// the number of successfully inserted and subsequently removed segments
// matches the expected totals, the test confirms the buffer's reliability
// and efficiency in managing dynamic and high-volume data scenarios.
func TestFuzzRcv(t *testing.T) {
	ring := NewRingBufferRcv[int](10, 10)

	seqIns := 0
	seqRem := 0
	randSource := rand.New(rand.NewSource(42))

	for j := 0; j < 10000; j++ {
		rnd := randSource.Intn(int(ring.Capacity())) + 1

		j := 0
		for i := rnd - 1; i >= 0; i-- {
			seg := newRcvSegment(uint32(seqIns+i), 0)
			inserted := ring.Insert(seg)
			if inserted == RcvInserted {
				j++
			}
		}
		seqIns += j

		seqRem += removeUntilNil(ring)

	}
	assert.Equal(t, 54948, seqIns)
	assert.Equal(t, 54948, seqRem)
}

func TestRemoveBlocking(t *testing.T) {
	// Create a ring buffer with a capacity of 10 and current limit also set to 10
	ring := NewRingBufferRcv[string](10, 10)

	// Start a goroutine that will simulate a delayed insert
	go func() {
		for i := 0; i < 10; i++ {
			time.Sleep(50 * time.Millisecond) // Delay the insert to allow remove to block
			segment := &RcvSegment[string]{sn: uint32(9 - i), data: "test"}
			status := ring.Insert(segment)
			assert.Equal(t, status, RcvInserted)
		}
	}()

	// Try to remove a segment, expecting this call to block until the goroutine inserts one
	i := 0
	for {
		removedSegment := ring.RemoveBlocking()
		if removedSegment == nil {
			break
		}
		assert.Equal(t, removedSegment.data, "test")
		if i == 9 {
			ring.Close()
		}
		i++
	}
	assert.Equal(t, i, 10)
}

func TestRemoveBlockingParallel(t *testing.T) {
	// Create a ring buffer with a capacity of 10 and current limit also set to 10
	ring := NewRingBufferRcv[string](10, 10)

	// Start a goroutine that will simulate a delayed insert
	go func() {
		for i := 0; i < 5; i++ {
			time.Sleep(100 * time.Millisecond) // Delay the insert to allow remove to block
			segment := &RcvSegment[string]{sn: uint32(i), data: "test"}
			status := ring.Insert(segment)
			assert.Equal(t, status, RcvInserted)
		}
	}()
	go func() {
		for i := 9; i >= 5; i-- {
			time.Sleep(100 * time.Millisecond) // Delay the insert to allow remove to block
			segment := &RcvSegment[string]{sn: uint32(i), data: "test"}
			status := ring.Insert(segment)
			assert.Equal(t, status, RcvInserted)
		}
	}()

	// Try to remove a segment, expecting this call to block until the goroutine inserts one
	i := 0
	for {
		removedSegment := ring.RemoveBlocking()
		if removedSegment == nil {
			break
		}
		assert.Equal(t, removedSegment.data, "test")
		if i == 9 {
			ring.Close()
		}
		i++
	}
	assert.Equal(t, i, 10)
}

// removeUntilNil is a helper function used in various tests to remove
// segments from the ring buffer until a nil segment is encountered, which
// signifies that the buffer is empty. This function serves as a utility
// to clean up the buffer by sequentially removing all present segments,
// allowing tests to validate the correctness of the buffer's size and removal
// logic. It iterates over the remove operation, counting the number of
// successful removals, and returns this count.
func removeUntilNil(ring *RingBufferRcv[int]) int {
	seg := ring.Remove()
	i := 0
	for seg != nil {
		seg = ring.Remove()
		i++
	}
	return i
}
