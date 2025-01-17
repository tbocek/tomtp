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
	hasData    bool
}

type RingBufferSnd[T any] struct {
	buffer       []*SndSegment[T]
	capacity     uint64
	targetLimit  uint64
	currentLimit uint64
	senderIndex  uint64
	minSnConn    uint64
	nextSnConn   uint64
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
		minSnConn:    0,
		nextSnConn:   0,
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
		if limit < (ring.nextSnConn - ring.minSnConn) {
			//need to set targetLimit
			ring.targetLimit = limit
			ring.currentLimit = ring.nextSnConn - ring.minSnConn
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

func (ring *RingBufferSnd[T]) InsertProducerBlocking(dataProducer func(snConn uint64) (T, int, error)) (int, SndInsertStatus, error) {
	ring.mu.Lock()
	defer ring.mu.Unlock()

	if ring.size == ring.currentLimit {
		ring.cond.Wait()
	}

	data, dataLen, err := dataProducer(ring.nextSnConn)
	if err != nil {
		return 0, 0, err
	}

	_, status := ring.insert(data)
	return dataLen, status, nil
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
	if ring.buffer[ring.nextSnConn%ring.currentLimit] != nil {
		return true
	}
	return false
}

func (ring *RingBufferSnd[T]) insert(data T) (uint64, SndInsertStatus) {
	if ring.isFull() {
		return 0, SndOverflow
	}

	segment := SndSegment[T]{
		snConn: ring.nextSnConn,
		data:   data,
	}

	ring.buffer[segment.snConn%ring.currentLimit] = &segment // Adjust index calculation
	ring.size++
	ring.nextSnConn = (ring.nextSnConn + 1) % globalSnLimit

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
	for i := ring.minSnConn; i < ring.nextSnConn; i = (i + 1) % globalSnLimit {
		retSeg = ring.buffer[ring.minSnConn]
	}

	//data packets that do not need acks can be removed. The first paket always has to be acked.
	if retSeg != nil {
		if !retSeg.hasData && retSeg.snConn > 0 {
			ring.remove(retSeg.snConn)
		}
	}

	return sleepMillis, retSeg
}
