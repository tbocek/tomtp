package tomtp

import (
	"fmt"
	"sync"
)

//The receiving buffer gets segments that can be out of order. That means, the insert needs
//to store the segments out of order. The remove of segments affect those segments
//that are in order

type RcvInsertStatus uint8

const (
	RcvInserted RcvInsertStatus = iota
	RcvOverflow
	RcvDuplicate
)

type RcvSegment[T any] struct {
	sn   uint32
	data T
}

type RingBufferRcv[T any] struct {
	buffer       []*RcvSegment[T]
	capacity     uint32
	targetLimit  uint32
	currentLimit uint32
	minSn        uint32
	maxSn        uint32
	size         uint32
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

	if segment.sn >= maxSn {
		return RcvOverflow
	} else if segment.sn < ring.minSn {
		//we already delivered this segment, don't add
		return RcvDuplicate
	} else if ring.buffer[index] != nil {
		//we may receive a duplicate, don't add
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
