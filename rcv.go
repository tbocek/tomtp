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

type RcvBuffer struct {
	segments                   *skipList[packetKey, []byte]
	nextInOrderOffsetToWaitFor uint64 // Next expected offset
}

type ReceiveBuffer struct {
	streams    map[uint32]*RcvBuffer
	lastStream uint32
	capacity   int // Max buffer size
	size       int // Current size
	acks       []Ack
	mu         *sync.Mutex
}

func NewRcvBuffer() *RcvBuffer {
	return &RcvBuffer{
		segments: newSortedHashMap[packetKey, []byte](func(a, b packetKey, c, d []byte) bool { return a.less(b) }),
	}
}

func NewReceiveBuffer(capacity int) *ReceiveBuffer {
	return &ReceiveBuffer{
		streams:  make(map[uint32]*RcvBuffer),
		capacity: capacity,
		mu:       &sync.Mutex{},
	}
}

func (rb *ReceiveBuffer) Insert(streamId uint32, offset uint64, decodedData []byte) RcvInsertStatus {
	dataLen := len(decodedData)
	key := createPacketKey(offset, uint16(dataLen))

	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Get or create stream buffer
	stream := rb.streams[streamId]
	if stream == nil {
		stream = NewRcvBuffer()
		rb.streams[streamId] = stream
	}

	if rb.size+dataLen > rb.capacity {
		return RcvInsertBufferFull
	}

	//now we need to add the ack to the list even if it's a duplicate, as the ack may have been lost, we need
	//to send it again
	rb.acks = append(rb.acks, Ack{
		StreamOffset: offset,
		Len:          uint16(dataLen),
	})

	if offset+uint64(dataLen) < stream.nextInOrderOffsetToWaitFor {
		return RcvInsertDuplicate
	}

	if stream.segments.Contains(key) {
		return RcvInsertDuplicate
	}

	stream.segments.Put(key, decodedData)

	rb.size += dataLen

	return RcvInsertOk
}

func (rb *ReceiveBuffer) RemoveOldestInOrder(streamId uint32) (offset uint64, data []byte) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if len(rb.streams) == 0 {
		return 0, nil
	}

	stream := rb.streams[streamId]
	if stream == nil {
		return 0, nil
	}

	// Check if there is any dataToSend at all
	oldest := stream.segments.Min()
	if oldest == nil {
		return 0, nil
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
		return oldest.key.offset(), segmentVal
	} else if oldest.key.offset() > stream.nextInOrderOffsetToWaitFor {
		// Out of order; wait until segment offset available, signal that
		return 0, nil
	} else {
		//Dupe, overlap, do nothing. Here we could think about adding the non-overlapping part. But if
		//it's correctly implemented, this should not happen.
		return 0, nil
	}
}

func (rb *ReceiveBuffer) Size() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.size
}

func (rb *ReceiveBuffer) GetAck() *Ack {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if len(rb.acks) == 0 {
		return nil
	}
	retVal := &rb.acks[0]
	rb.acks = rb.acks[1:] //remove element 0
	return retVal
}
