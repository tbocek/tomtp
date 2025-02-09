package tomtp

import (
	"context"
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
	segments      *skipList[packetKey, *RcvSegment] // Store out-of-order segments
	nextOffset    uint64                            // Next expected offset
	capacity      int                               // Max buffer size
	size          int                               // Current size
	mu            *sync.Mutex
	acks          []Ack
	dataAvailable chan struct{} // Signal that data is available
}

func NewReceiveBuffer(capacity int) *ReceiveBuffer {
	return &ReceiveBuffer{
		segments:      newSortedHashMap[packetKey, *RcvSegment](func(a, b packetKey) bool { return a.less(b) }),
		capacity:      capacity,
		mu:            &sync.Mutex{},
		dataAvailable: make(chan struct{}, 1),
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

	// Signal that data is available (non-blocking send)
	select {
	case rb.dataAvailable <- struct{}{}:
	default: // Non-blocking to prevent deadlocks if someone is already waiting
	}

	return RcvInsertOk
}

func (rb *ReceiveBuffer) RemoveOldestInOrder(ctx context.Context) (*RcvSegment, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	for {
		// Check if there is any data at all
		oldest := rb.segments.Min()
		if oldest == nil {
			// No segments available, so wait
			rb.mu.Unlock()
			select {
			case <-rb.dataAvailable: // Wait for new segment signal
				rb.mu.Lock()
				continue // Recheck segments size
			case <-ctx.Done():
				rb.mu.Lock()
				return nil, ctx.Err() // Context cancelled
			}
		}

		if oldest.value.offset == rb.nextOffset {
			rb.segments.Remove(oldest.key)
			rb.size -= int(oldest.key.length())

			segment := oldest.value
			if segment.offset < rb.nextOffset {
				diff := rb.nextOffset - segment.offset
				segment.data = segment.data[diff:]
				segment.offset = rb.nextOffset
			}

			rb.nextOffset = segment.offset + uint64(len(segment.data))
			return segment, nil
		} else if oldest.value.offset > rb.nextOffset {
			// Out of order; wait until segment offset available, signal that
			rb.mu.Unlock()
			select {
			case <-rb.dataAvailable:
				rb.mu.Lock() //get new data signal, re-lock to ensure no one modifies
				continue     // Recheck segments size after getting the data
			case <-ctx.Done():
				rb.mu.Lock()
				return nil, ctx.Err()
			}
		} else {
			rb.segments.Remove(oldest.key)
			rb.size -= int(oldest.key.length())
			// Dupe data, loop to get more data if exist
		}
	}
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
