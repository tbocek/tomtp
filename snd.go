package tomtp

import (
	"fmt"
	"sync"
)

//The send buffer gets the segments in order, but needs to remove them out of order, depending
//on when the acks arrive. The send buffer should be able to adapt its size based on the receiver buffer

type SndInsertStatus uint8

const (
	SndInserted SndInsertStatus = iota
	SndOverflow
	SndNotASequence
)

type SndSegment[T any] struct {
	sn      uint32
	tMillis int64
	data    T
}

type RingBufferSnd[T any] struct {
	buffer       []*SndSegment[T]
	capacity     uint32
	targetLimit  uint32
	currentLimit uint32
	senderIndex  uint32
	minSn        uint32
	maxSn        uint32
	size         uint32
	mu           *sync.Mutex
	cond         *sync.Cond
}

func NewRingBufferSnd[T any](limit uint32, capacity uint32) *RingBufferSnd[T] {
	var mu sync.Mutex
	return &RingBufferSnd[T]{
		buffer:       make([]*SndSegment[T], capacity),
		capacity:     capacity,
		targetLimit:  0,
		currentLimit: limit,
		mu:           &mu,
		cond:         sync.NewCond(&mu),
	}
}

func (ring *RingBufferSnd[T]) Capacity() uint32 {
	return ring.capacity
}

func (ring *RingBufferSnd[T]) Limit() uint32 {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	return ring.currentLimit
}

func (ring *RingBufferSnd[T]) Free() uint32 {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	return ring.currentLimit - ring.size
}

func (ring *RingBufferSnd[T]) Size() uint32 {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	return ring.size
}

func (ring *RingBufferSnd[T]) SetLimit(limit uint32) {
	ring.mu.Lock()
	defer ring.mu.Unlock()

	if limit > ring.capacity {
		panic(fmt.Errorf("limit cannot exceed capacity  %v > %v", limit, ring.capacity))
	}
	ring.setLimitInternal(limit)

}

func (ring *RingBufferSnd[T]) setLimitInternal(limit uint32) {
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

	newBuffer := make([]*SndSegment[T], ring.capacity)
	for i := uint32(0); i < oldLimit; i++ {
		oldSegment := ring.buffer[i]
		if oldSegment != nil {
			newBuffer[oldSegment.sn%ring.currentLimit] = oldSegment
		}
	}
	ring.buffer = newBuffer
}

func (ring *RingBufferSnd[T]) InsertBlocking(segment *SndSegment[T]) SndInsertStatus {
	ring.mu.Lock()
	defer ring.mu.Unlock()

	if ring.size == ring.currentLimit {
		ring.cond.Wait()
	}

	return ring.insert(segment)
}

func (ring *RingBufferSnd[T]) Insert(segment *SndSegment[T]) SndInsertStatus {
	ring.mu.Lock()
	defer ring.mu.Unlock()

	return ring.insert(segment)
}

func (ring *RingBufferSnd[T]) insert(segment *SndSegment[T]) SndInsertStatus {
	if ring.buffer[ring.maxSn%ring.currentLimit] != nil {
		//is full
		return SndOverflow
	}

	if ring.maxSn != segment.sn && segment.sn != 0 {
		return SndNotASequence
	}

	ring.buffer[ring.maxSn%ring.currentLimit] = segment
	ring.size++
	ring.maxSn = segment.sn + 1

	if ring.size < ring.currentLimit {
		ring.cond.Signal()
	}

	return SndInserted
}

func (ring *RingBufferSnd[T]) Remove(sn uint32) *SndSegment[T] {
	ring.mu.Lock()
	defer ring.mu.Unlock()

	return ring.remove(sn)
}

func (ring *RingBufferSnd[T]) remove(sn uint32) *SndSegment[T] {
	index := sn % ring.currentLimit
	segment := ring.buffer[index]
	if segment == nil {
		return nil
	}
	if sn != segment.sn {
		fmt.Printf("sn mismatch %v/%v\n", sn, segment.sn)
		return nil
	}
	ring.buffer[index] = nil
	ring.size--

	if segment.sn == ring.minSn && ring.size != 0 {
		//search new min
		for i := uint32(1); i < ring.currentLimit; i++ {
			if ring.buffer[(segment.sn+i)%ring.currentLimit] != nil {
				ring.minSn = segment.sn + i
				break
			}
		}
	}

	if ring.targetLimit != 0 {
		ring.setLimitInternal(ring.targetLimit)
	}

	if ring.size < ring.currentLimit {
		ring.cond.Signal()
	}

	return segment
}

func (ring *RingBufferSnd[T]) Reschedule(t int64) *SndSegment[T] {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	//TODO:
	return ring.buffer[ring.minSn%ring.currentLimit]
}
