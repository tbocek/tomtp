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

type RcvBuffer struct {
	segments                   *skipList[packetKey, []byte]
	nextInOrderOffsetToWaitFor uint64 // Next expected offset
}

type ReceiveBuffer struct {
	streams    *linkedHashMap[uint32, *RcvBuffer]
	lastStream uint32

	capacity      int // Max buffer size
	size          int // Current size
	mu            *sync.Mutex
	acks          []Ack
	dataAvailable chan struct{} // Signal that dataToSend is available
}

func NewRcvBuffer() *RcvBuffer {
	return &RcvBuffer{
		segments: newSortedHashMap[packetKey, []byte](func(a, b packetKey) bool { return a.less(b) }),
	}
}

func NewReceiveBuffer(capacity int) *ReceiveBuffer {
	return &ReceiveBuffer{
		streams:       newLinkedHashMap[uint32, *RcvBuffer](),
		capacity:      capacity,
		mu:            &sync.Mutex{},
		dataAvailable: make(chan struct{}, 1),
	}
}

func (rb *ReceiveBuffer) Insert(streamId uint32, offset uint64, decodedData []byte) RcvInsertStatus {
	dataLen := len(decodedData)
	key := createPacketKey(offset, uint16(dataLen))

	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Get or create stream buffer
	entry := rb.streams.Get(streamId)
	if entry == nil {
		stream := NewRcvBuffer()
		entry = rb.streams.Put(streamId, stream)
	}
	stream := entry.value

	if offset+uint64(dataLen) < stream.nextInOrderOffsetToWaitFor {
		return RcvInsertDuplicate
	}

	if stream.segments.Contains(key) {
		return RcvInsertDuplicate
	}

	if rb.size+dataLen > rb.capacity {
		return RcvInsertBufferFull
	}

	stream.segments.Put(key, decodedData)
	rb.acks = append(rb.acks, Ack{
		StreamOffset: offset,
		Len:          uint16(dataLen),
	})

	rb.size += dataLen

	// Signal that dataToSend is available (non-blocking send)
	select {
	case rb.dataAvailable <- struct{}{}:
	default: // Non-blocking to prevent deadlocks if someone is already waiting
	}

	return RcvInsertOk
}

func (rb *ReceiveBuffer) RemoveOldestInOrderBlocking(ctx context.Context, streamId uint32) (offset uint64, data []byte, err error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.streams.Size() == 0 {
		return 0, nil, nil
	}

	streamPair := rb.streams.Get(streamId)
	if streamPair == nil {
		return 0, nil, nil
	}
	stream := streamPair.value
	streamId = streamPair.key

	for {
		// Check if there is any dataToSend at all
		oldest := stream.segments.Min()
		if oldest == nil {
			// No segments available, so wait
			rb.mu.Unlock()
			select {
			case <-rb.dataAvailable: // Wait for new segment signal
				rb.mu.Lock()
				continue // Recheck segments size
			case <-ctx.Done():
				rb.mu.Lock()
				return 0, nil, ctx.Err() // Context cancelled
			}
		}

		if oldest.key.offset() == stream.nextInOrderOffsetToWaitFor {
			stream.segments.Remove(oldest.key)
			rb.size -= int(oldest.key.length())

			segmentVal := oldest.value
			segmentKey := oldest.key
			off := segmentKey.offset()
			if off < stream.nextInOrderOffsetToWaitFor {
				diff := stream.nextInOrderOffsetToWaitFor - segmentKey.offset()
				segmentVal = segmentVal[diff:]
				off = stream.nextInOrderOffsetToWaitFor
			}

			stream.nextInOrderOffsetToWaitFor = off + uint64(len(segmentVal))
			return oldest.key.offset(), segmentVal, nil
		} else if oldest.key.offset() > stream.nextInOrderOffsetToWaitFor {
			// Out of order; wait until segment offset available, signal that
			rb.mu.Unlock()
			select {
			case <-rb.dataAvailable:
				rb.mu.Lock() //get new dataToSend signal, re-lock to ensure no one modifies
				continue     // Recheck segments size after getting the dataToSend
			case <-ctx.Done():
				rb.mu.Lock()
				return 0, nil, ctx.Err()
			}
		} else {
			//Dupe, overlap, do nothing. Here we could think about adding the non-overlapping part. But if
			//its correctly implemented, this should not happen.
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
