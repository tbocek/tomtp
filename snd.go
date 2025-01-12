package tomtp

import (
	"fmt"
	"math"
	"sync"
)

//The send buffer gets the segments in order, but needs to remove them out of order, depending
//on when the acks arrive. The send buffer should be able to adapt its size based on the receiver buffer

type SndInsertStatus uint8

const (
	SndInserted SndInsertStatus = iota
	SndOverflow
	globalSnLimit = math.MaxUint64
)

type SndSegment[T any] struct {
	sn         uint64
	data       T
	sentMillis uint64
}

type RingBufferSnd[T any] struct {
	buffer       []*SndSegment[T]
	capacity     uint64
	targetLimit  uint64
	currentLimit uint64
	senderIndex  uint64
	minSn        uint64
	maxSn        uint64
	size         uint64
	mu           *sync.Mutex
	cond         *sync.Cond
}

func NewRingBufferSnd[T any](limit uint64, capacity uint64) *RingBufferSnd[T] {
	var mu sync.Mutex
	return &RingBufferSnd[T]{
		buffer:       make([]*SndSegment[T], capacity),
		capacity:     capacity,
		targetLimit:  0,
		currentLimit: limit,
		minSn:        1,
		maxSn:        1,
		mu:           &mu,
		cond:         sync.NewCond(&mu),
	}
}

func (ring *RingBufferSnd[T]) Capacity() uint64 {
	return ring.capacity
}

func (ring *RingBufferSnd[T]) Limit() uint64 {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	return ring.currentLimit
}

func (ring *RingBufferSnd[T]) Free() uint64 {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	return ring.currentLimit - ring.size
}

func (ring *RingBufferSnd[T]) Size() uint64 {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	return ring.size
}

func (ring *RingBufferSnd[T]) SetLimit(limit uint64) {
	ring.mu.Lock()
	defer ring.mu.Unlock()

	if limit > ring.capacity {
		panic(fmt.Errorf("limit cannot exceed capacity  %v > %v", limit, ring.capacity))
	}
	ring.setLimitInternal(limit)
	if !ring.isFull() {
		ring.cond.Signal()
	}

}

func (ring *RingBufferSnd[T]) setLimitInternal(limit uint64) {
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
	for i := uint64(0); i < oldLimit; i++ {
		oldSegment := ring.buffer[i]
		if oldSegment != nil {
			newBuffer[(oldSegment.sn-1)%ring.currentLimit] = oldSegment
		}
	}
	ring.buffer = newBuffer
}

func (ring *RingBufferSnd[T]) InsertBlocking(data T) (uint64, SndInsertStatus) {
	ring.mu.Lock()
	defer ring.mu.Unlock()

	if ring.size == ring.currentLimit {
		ring.cond.Wait()
	}

	return ring.insert(data)
}

func (ring *RingBufferSnd[T]) Insert(data T) (uint64, SndInsertStatus) {
	ring.mu.Lock()
	defer ring.mu.Unlock()

	return ring.insert(data)
}

func (ring *RingBufferSnd[T]) isFull() bool {
	if ring.size == ring.currentLimit {
		return true
	}
	if ring.buffer[(ring.maxSn-1)%ring.currentLimit] != nil {
		return true
	}
	return false
}

func (ring *RingBufferSnd[T]) insert(data T) (uint64, SndInsertStatus) {
	if ring.isFull() {
		return 0, SndOverflow
	}

	segment := SndSegment[T]{
		sn:   ring.maxSn,
		data: data,
	}

	ring.buffer[(segment.sn-1)%ring.currentLimit] = &segment // Adjust index calculation
	ring.size++
	ring.maxSn = (segment.sn + 1) % globalSnLimit
	if ring.maxSn == 0 {
		ring.maxSn = 1 // Skip 0 as it's invalid
	}

	return segment.sn, SndInserted
}

func (ring *RingBufferSnd[T]) Remove(sn uint64) *SndSegment[T] {
	ring.mu.Lock()
	defer ring.mu.Unlock()

	return ring.remove(sn)
}

func (ring *RingBufferSnd[T]) remove(sn uint64) *SndSegment[T] {
	if sn == 0 {
		return nil // 0 is invalid
	}

	index := (sn - 1) % ring.currentLimit
	segment := ring.buffer[index]
	if segment == nil {
		return nil
	}
	if sn != segment.sn {
		fmt.Printf("sn mismatch %v/%v\n", ring.minSn, segment.sn)
		return nil
	}
	ring.buffer[index] = nil
	ring.size--

	if segment.sn == ring.minSn && ring.size != 0 {
		//search new min
		for i := uint64(1); i < ring.currentLimit; i++ {
			newSn := (segment.sn + i) % globalSnLimit
			if newSn == 0 {
				newSn = 1 // Skip 0 as it's invalid
			}
			if ring.buffer[(newSn-1)%ring.currentLimit] != nil {
				ring.minSn = newSn
				break
			}
		}
	}

	if ring.targetLimit != 0 {
		ring.setLimitInternal(ring.targetLimit)
	}

	if !ring.isFull() {
		ring.cond.Signal()
	}

	return segment
}

func (ring *RingBufferSnd[T]) ReadyToSend(rtoMillis uint64, nowMillis uint64) (sleepMillis uint64, readyToSend *SndSegment[T]) {
	ring.mu.Lock()
	defer ring.mu.Unlock()

	sleepMillis = 200
	var retSeg *SndSegment[T]

	//TODO: for loop is not ideal, but good enough for initial solution
	for i := ring.minSn; i != ring.maxSn; i = (i + 1) % globalSnLimit {
		if i == 0 {
			i = 1 // Skip 0 as it's invalid
		}
		seg := ring.buffer[(i-1)%ring.currentLimit]
		if seg != nil {
			if seg.sentMillis != 0 && seg.sentMillis+rtoMillis > nowMillis {
				idle := (seg.sentMillis + rtoMillis) - nowMillis
				if idle < sleepMillis {
					sleepMillis = idle
				}
			} else if seg.sentMillis == 0 || seg.sentMillis+rtoMillis <= nowMillis {
				if retSeg == nil {
					seg.sentMillis = nowMillis
					retSeg = seg
				} else {
					sleepMillis = 0
					break
				}
			}
		}
	}

	return sleepMillis, retSeg
}
