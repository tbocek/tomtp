package tomtp

import (
	"sync"
)

type RcvInsertStatus int

const (
	RcvInsertOk RcvInsertStatus = iota
	RcvInsertDuplicate
	RcvInsertBufferFull
)

type RcvSegment struct {
	streamId uint32
	offset   uint64
	data     []byte
}

type ReceiveBuffer struct {
	segments   *SortedHashMap[uint64, *RcvSegment] // Store out-of-order segments
	nextOffset uint64                              // Next expected offset
	capacity   int                                 // Max buffer size
	size       int                                 // Current size
	mu         *sync.Mutex
	closed     bool
	acks       []Ack
}

func NewReceiveBuffer(capacity int) *ReceiveBuffer {
	return &ReceiveBuffer{
		segments: NewSortedHashMap[uint64, *RcvSegment](func(a, b uint64) bool { return a < b }),
		capacity: capacity,
		mu:       &sync.Mutex{},
	}
}

func (rb *ReceiveBuffer) Insert(segment *RcvSegment) RcvInsertStatus {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Check if segment offset is less than next expected offset

	//todo we may receive first a packet with the same offset but smaller len, then a packet with the same
	//offset, but a larger len. We want to keep this data
	if segment.offset < rb.nextOffset {
		return RcvInsertDuplicate
	}
	// Check if already exists
	if existing := rb.segments.Get(segment.offset); existing != nil {
		return RcvInsertDuplicate
	}

	// Check capacity
	// the sender does not handle arbitrary length well, so just ignore even if there is a bit capacity there
	if rb.size >= rb.capacity {
		return RcvInsertBufferFull
	}

	// Insert segment
	rb.segments.Put(segment.offset, segment)
	rb.size++

	return RcvInsertOk
}

func (rb *ReceiveBuffer) RemoveOldestInOrder() *RcvSegment {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Get oldest segment
	oldest := rb.segments.Min()
	if oldest == nil {
		return nil
	}

	// Check if it matches next expected offset
	if oldest.Value.offset != rb.nextOffset {
		return nil
	}

	// Remove and return segment
	rb.segments.Remove(oldest.Key)
	rb.size--
	data := oldest.Value.data
	rb.nextOffset = oldest.Value.offset + uint64(len(data))

	return oldest.Value
}

// Close marks the buffer as closed - no more insertions allowed
func (rb *ReceiveBuffer) Close() {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.closed = true
}

// Helper methods

// getSegmentSize returns the size of a segment for capacity tracking
func (rb *ReceiveBuffer) getSegmentSize(segment *RcvSegment) int {
	switch v := any(segment.data).(type) {
	case []byte:
		return len(v)
	case string:
		return len(v)
	default:
		return 1 // Default to 1 for non-sized types
	}
}

func (rb *ReceiveBuffer) Size() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.size
}

func (rb *ReceiveBuffer) IsClosed() bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.closed
}

func (rb *ReceiveBuffer) GetAcks() []Ack {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	numAcks := len(rb.acks)
	if numAcks == 0 {
		return nil
	}

	if numAcks <= 15 {
		acks := rb.acks
		rb.acks = nil
		return acks
	}

	acks := rb.acks[:15]
	rb.acks = rb.acks[15:]
	return acks
}
