package tomtp

import (
	"fmt"
	"sort"
	"sync"
)

//The receiving buffer gets segments that can be out of order. That means, the insert needs
//to store the segments out of order. The remove of segments affect those segments
//that are in order

type RcvInsertStatus uint8

const (
	RcvInserted RcvInsertStatus = iota
	RcvNothing
	RcvOverflow
	RcvDuplicate
)

type RcvSegment[T any] struct {
	sn         uint32
	data       T
	insertedAt uint64
}

type RingBufferRcv[T any] struct {
	buffer       []*RcvSegment[T]
	capacity     uint32
	targetLimit  uint32
	currentLimit uint32
	minSn        uint32
	maxSn        uint32
	size         uint32
	toAck        []uint32
	closed       bool
	mu           *sync.Mutex
	cond         *sync.Cond
}

// NewRingBufferRcv creates a new receiving buffer
func NewRingBufferRcv[T any](limit uint32, capacity uint32) *RingBufferRcv[T] {
	var mu sync.Mutex
	return &RingBufferRcv[T]{
		buffer:       make([]*RcvSegment[T], capacity),
		capacity:     capacity,
		targetLimit:  0,
		currentLimit: limit,
		closed:       false,
		mu:           &mu,
		cond:         sync.NewCond(&mu),
	}
}

// Capacity The current total capacity of the receiving buffer. This is the total size.
func (ring *RingBufferRcv[T]) Capacity() uint32 {
	return ring.capacity
}

func (ring *RingBufferRcv[T]) Limit() uint32 {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	return ring.currentLimit
}

func (ring *RingBufferRcv[T]) Free() uint32 {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	return ring.currentLimit - ring.size
}

func (ring *RingBufferRcv[T]) Size() uint32 {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	return ring.size
}

func (ring *RingBufferRcv[T]) SetLimit(limit uint32) {
	ring.mu.Lock()
	defer ring.mu.Unlock()

	if limit > ring.capacity {
		panic(fmt.Errorf("limit cannot exceed capacity  %v > %v", limit, ring.capacity))
	}
	ring.setLimitInternal(limit)

}

func (ring *RingBufferRcv[T]) setLimitInternal(limit uint32) {
	if limit == ring.currentLimit {
		// no change
		ring.targetLimit = 0
		return
	}

	oldLimit := ring.currentLimit
	if ring.currentLimit > limit {
		//decrease limit
		if (ring.currentLimit - limit) > (ring.maxSn - ring.minSn) {
			//need to set targetLimit
			ring.targetLimit = limit
			ring.currentLimit = ring.maxSn - ring.minSn
		} else {
			ring.targetLimit = 0
			ring.currentLimit = limit

		}
	} else {
		//increase limit
		ring.targetLimit = 0
		ring.currentLimit = limit
	}

	newBuffer := make([]*RcvSegment[T], ring.capacity)
	for i := uint32(0); i < oldLimit; i++ {
		oldSegment := ring.buffer[i]
		if oldSegment != nil {
			newBuffer[oldSegment.sn%ring.currentLimit] = oldSegment
		}
	}
	ring.buffer = newBuffer
}

func (ring *RingBufferRcv[T]) Insert(segment *RcvSegment[T]) RcvInsertStatus {
	ring.mu.Lock()
	defer ring.mu.Unlock()

	maxSn := ring.minSn + ring.currentLimit
	index := segment.sn % ring.currentLimit
	ring.addSegmentToAckOrdered(segment.sn)

	if segment.sn >= maxSn {
		return RcvOverflow
	} else if segment.sn < ring.minSn {
		//we already delivered this segment, don't add
		//but return the ack info again, as acks may
		//have been lost
		return RcvDuplicate
	} else if ring.buffer[index] != nil {
		//we may receive a duplicate, don't add
		//but return the ack info again, as acks may
		//have been lost
		return RcvDuplicate
	}

	ring.buffer[index] = segment
	ring.size++
	if ring.available() != nil {
		ring.cond.Signal()
	}

	if segment.sn+1 > ring.maxSn {
		ring.maxSn = segment.sn + 1
	}

	return RcvInserted
}

func (ring *RingBufferRcv[T]) addSegmentToAckOrdered(sn uint32) {
	// Find the correct position to insert the new sequence number
	index := sort.Search(len(ring.toAck), func(i int) bool { return ring.toAck[i] >= sn })

	// Insert the sequence number into the correct position
	if index < len(ring.toAck) && ring.toAck[index] == sn {
		// If sn is already in the list, we don't add it again
		return
	}

	ring.toAck = append(ring.toAck, 0)             // Expand the slice by one element
	copy(ring.toAck[index+1:], ring.toAck[index:]) // Shift elements to the right
	ring.toAck[index] = sn                         // Insert the new sequence number

}

func (ring *RingBufferRcv[T]) Close() {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	//set flag and just signal waiting goroutines
	ring.closed = true
	ring.cond.Signal()
}

func (ring *RingBufferRcv[T]) RemoveBlocking() *RcvSegment[T] {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	if ring.available() == nil && !ring.closed {
		ring.cond.Wait()
	}
	return ring.remove()
}

func (ring *RingBufferRcv[T]) Remove() *RcvSegment[T] {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	return ring.remove()
}

func (ring *RingBufferRcv[T]) available() *RcvSegment[T] {
	if ring.size == 0 {
		return nil
	}
	return ring.buffer[ring.minSn%ring.currentLimit]
}

func (ring *RingBufferRcv[T]) remove() *RcvSegment[T] {
	//fast path
	segment := ring.available()
	if segment == nil {
		return nil
	}

	ring.buffer[ring.minSn%ring.currentLimit] = nil
	ring.minSn = segment.sn + 1
	ring.size--

	//we have not reached target limit, now we have 1 item less, set it
	if ring.targetLimit != 0 {
		ring.setLimitInternal(ring.targetLimit)
	}

	return segment
}

func (ring *RingBufferRcv[T]) CalcRleAck() (startSn uint32, rleAck uint64, hasMore bool) {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	return calcRleAck(ring.toAck)
}

func (ring *RingBufferRcv[T]) HasAcks() bool {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	return len(ring.toAck) > 0
}

/*
LLM Prompt:

# Task Description:

You are given an array of sequence numbers, such as [0, 1, 2, 3, 5, 6], which represents received packet
sequence numbers. The goal is to calculate the length of consecutive sequences and the gaps between them.

## Example:

Given the input array [0, 1, 2, 3, 5, 6]:

1. The sequence starts at 0 with a length of 4 (indicating the presence of sequence numbers 0 through 3).
2. There is a gap of length 1 (indicating the absence of sequence number 4).
3. Another sequence of length 2 follows (indicating the presence of sequence numbers 5 and 6).

So, the output should be:
- startSn: 0 (indicating the start of the first sequence),
- An encoded representation of the sequence and gaps (e.g., [4, 1, 2] for the example above),
- A flag indicating whether there are more sequence numbers to process.

## Implementation:

You will need to:

1. Iterate through the input array, identifying consecutive sequences and gaps.
2. Encode the lengths of these sequences and gaps into a bitset.
3. Return the start of the first sequence (startSn), the encoded bitset (rleAck), and a flag (hasMore)
indicating whether the entire array was processed or if there are more elements to process due to space limitations.

The function signature is as follows:

	func calcRleAck(toAck []uint32) (startSn uint32, rleAck uint64, hasMore bool) {
	    // Implementation here
	}
*/
func calcRleAck(toAck []uint32) (startSn uint32, rleAck uint64, hasMore bool) {
	if len(toAck) == 0 {
		return 0, 0, false
	}

	start := toAck[0]
	length := uint32(1)
	bs := New(0)
	n := 0

	var isNotFull bool
	for i := 1; i < len(toAck); i++ {
		if toAck[i] == toAck[i-1]+1 {
			length++
		} else {
			n, isNotFull = EncodeLength(length, bs, n)
			if !isNotFull {
				// We stop encoding if the bitset is full
				toAck = toAck[i-1:] // Keep the unprocessed entries in the array
				return start, bs.BitSet(), true
			}

			gap := toAck[i] - toAck[i-1] - 1
			n, isNotFull = EncodeLength(gap, bs, n)
			if !isNotFull {
				// We stop encoding if the bitset is full
				toAck = toAck[i-1:] // Keep the unprocessed entries in the array
				return start, bs.BitSet(), true
			}

			length = 1 // Reset length for the new sequence
		}
	}

	// Encode the last sequence length
	n, isNotFull = EncodeLength(length, bs, n)

	// If we reach the end, remove all processed elements
	if isNotFull {
		toAck = toAck[len(toAck):] // Clear the array
	} else {
		toAck = toAck[len(toAck)-1:] // Keep the last unprocessed element
	}

	return start, bs.BitSet(), !isNotFull
}
