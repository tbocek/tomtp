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
	offset uint64
	data   []byte
}

type ReceiveBuffer struct {
	segments   *SortedHashMap[PacketKey, *RcvSegment] // Store out-of-order segments
	nextOffset uint64                                 // Next expected offset
	capacity   int                                    // Max buffer size
	size       int                                    // Current size
	mu         *sync.Mutex
	acks       []Ack
}

func NewReceiveBuffer(capacity int) *ReceiveBuffer {
	return &ReceiveBuffer{
		segments: NewSortedHashMap[PacketKey, *RcvSegment](func(a, b PacketKey) bool { return a.less(b) }),
		capacity: capacity,
		mu:       &sync.Mutex{},
	}
}

func (rb *ReceiveBuffer) Insert(segment *RcvSegment) RcvInsertStatus {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	dataLen := len(segment.data)
	if segment.offset+uint64(dataLen) < rb.nextOffset {
		return RcvInsertDuplicate
	}

	key := createPacketKey(segment.offset, uint16(dataLen))
	if rb.segments.Contains(key) {
		return RcvInsertDuplicate
	}

	if rb.size+dataLen > rb.capacity {
		return RcvInsertBufferFull
	}

	rb.segments.Put(key, segment)
	rb.acks = append(rb.acks, Ack{
		StreamOffset: segment.offset,
		Len:          uint16(dataLen),
	})

	rb.size += dataLen

	return RcvInsertOk
}

func (rb *ReceiveBuffer) RemoveOldestInOrder() *RcvSegment {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Get the oldest segment, check if we have data in order
	oldest := rb.segments.Min()
	if oldest == nil || oldest.Value.offset > rb.nextOffset {
		return nil
	}

	rb.segments.Remove(oldest.Key)
	rb.size -= int(oldest.Key.length())

	segment := oldest.Value
	if segment.offset < rb.nextOffset {
		diff := rb.nextOffset - segment.offset
		segment.data = segment.data[diff:]
		segment.offset = rb.nextOffset
	}

	rb.nextOffset = segment.offset + uint64(len(segment.data))
	return segment
}

func (rb *ReceiveBuffer) Size() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.size
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
