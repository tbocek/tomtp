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
	globalSnLimit = MaxUint48
)

type SndSegment[T any] struct {
	snConn     uint64
	data       T
	sentMillis uint64
}

type RingBufferSnd[T any] struct {
	buffer       []*SndSegment[T]
	capacity     uint64
	targetLimit  uint64
	currentLimit uint64
	senderIndex  uint64
	minSnConn    uint64
	maxSnConn    uint64
	size         uint64
	req          ConnectionRequests
	mu           *sync.Mutex
	cond         *sync.Cond
}

type ConnectionRequests struct {
	requestConnClose   bool
	requestStreamClone []uint32
}

func NewRingBufferSnd[T any](limit uint64, capacity uint64) *RingBufferSnd[T] {
	var mu sync.Mutex
	return &RingBufferSnd[T]{
		buffer:       make([]*SndSegment[T], capacity),
		capacity:     capacity,
		targetLimit:  0,
		currentLimit: limit,
		minSnConn:    0,
		maxSnConn:    0,
		req:          ConnectionRequests{requestConnClose: false, requestStreamClone: make([]uint32, 0)},
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
		if limit < (ring.maxSnConn - ring.minSnConn + 1) {
			//need to set targetLimit
			ring.targetLimit = limit
			ring.currentLimit = ring.maxSnConn - ring.minSnConn + 1
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
			newBuffer[oldSegment.snConn%ring.currentLimit] = oldSegment
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
	if ring.buffer[ring.maxSnConn+1%ring.currentLimit] != nil {
		return true
	}
	return false
}

func (ring *RingBufferSnd[T]) insert(data T) (uint64, SndInsertStatus) {
	if ring.isFull() {
		return 0, SndOverflow
	}

	var segment SndSegment[T]
	if ring.size == 0 {
		segment = SndSegment[T]{
			snConn: ring.maxSnConn,
			data:   data,
		}
	} else {
		segment = SndSegment[T]{
			snConn: ring.maxSnConn + 1,
			data:   data,
		}
	}

	ring.buffer[segment.snConn%ring.currentLimit] = &segment // Adjust index calculation
	ring.size++
	ring.maxSnConn = segment.snConn % globalSnLimit

	return segment.snConn, SndInserted
}

func (ring *RingBufferSnd[T]) Remove(sn uint64) *SndSegment[T] {
	ring.mu.Lock()
	defer ring.mu.Unlock()

	return ring.remove(sn)
}

func (ring *RingBufferSnd[T]) remove(sn uint64) *SndSegment[T] {
	index := sn % ring.currentLimit
	segment := ring.buffer[index]
	if segment == nil {
		return nil
	}
	if sn != segment.snConn {
		fmt.Printf("sn mismatch %v/%v\n", ring.minSnConn, segment.snConn)
		return nil
	}
	ring.buffer[index] = nil
	ring.size--

	//search new min -- TODO make this more efficient
	if segment.snConn == ring.minSnConn && ring.size != 0 {
		for i := uint64(0); i < ring.currentLimit; i++ {
			newSn := (segment.snConn + i) % globalSnLimit
			if ring.buffer[newSn%ring.currentLimit] != nil {
				ring.minSnConn = newSn
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

func (ring *RingBufferSnd[T]) ReadyToSend(nowMillis uint64) (sleepMillis uint64, readyToSend *SndSegment[T]) {
	ring.mu.Lock()
	defer ring.mu.Unlock()

	sleepMillis = 200
	var retSeg *SndSegment[T]

	//TODO: for loop is not ideal, but good enough for initial solution
	for i := ring.minSnConn; i != ring.maxSnConn; i = (i + 1) % globalSnLimit {
		retSeg = ring.buffer[ring.minSnConn]
	}

	return sleepMillis, retSeg
}
