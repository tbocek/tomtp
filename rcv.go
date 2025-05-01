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
	segments                   *skipList[packetKey, *Data]
	nextInOrderOffsetToWaitFor uint64 // Next expected offset
}

type Data struct {
	data    []byte
	isClose bool
}

func (d *Data) less(other *Data) bool {
	if len(d.data) < len(other.data) {
		return true
	}
	return false
}

type RcvBufferAck struct {
	segments                   *skipList[packetKey, *Ack]
	nextInOrderOffsetToWaitFor uint64 // Next expected offset
}

type ReceiveBuffer struct {
	streams    map[uint32]*RcvBuffer
	lastStream uint32
	capacity   int // Max buffer size
	size       int // Current size
	ackList    []*Ack
	mu         *sync.Mutex
}

func NewRcvBuffer() *RcvBuffer {
	return &RcvBuffer{
		segments: newSortedHashMap[packetKey, *Data](func(a, b packetKey, c, d *Data) bool {
			if a.less(b) {
				return true
			}
			if a == b {
				return d.less(c)
			}
			return false
		}),
	}
}

func NewReceiveBuffer(capacity int) *ReceiveBuffer {
	return &ReceiveBuffer{
		streams:  make(map[uint32]*RcvBuffer),
		capacity: capacity,
		ackList:  []*Ack{},
		mu:       &sync.Mutex{},
	}
}

func (rb *ReceiveBuffer) Insert(streamId uint32, offset uint64, decodedData []byte, isClose bool) RcvInsertStatus {
	dataLen := len(decodedData)

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

	key := createPacketKey(offset, uint16(dataLen))

	//now we need to add the ack to the list even if it's a duplicate,
	//as the ack may have been lost, we need to send it again
	if dataLen > 0 { //only ack if we have data
		rb.ackList = append(rb.ackList, &Ack{streamId: streamId, offset: offset, len: uint16(dataLen)})
	}

	if offset+uint64(dataLen) < stream.nextInOrderOffsetToWaitFor {
		return RcvInsertDuplicate
	}

	if stream.segments.Contains(key) {
		return RcvInsertDuplicate
	}

	if dataLen == 0 {
		key = createPacketKey(offset, uint16(65535))
	}

	stream.segments.Put(key, &Data{
		data:    decodedData,
		isClose: isClose,
	})

	rb.size += dataLen

	return RcvInsertOk
}

func (rb *ReceiveBuffer) RemoveOldestInOrder(streamId uint32) (offset uint64, data *Data) {
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
			segmentVal.data = segmentVal.data[diff:]
			off = stream.nextInOrderOffsetToWaitFor
		}

		stream.nextInOrderOffsetToWaitFor = off + uint64(len(segmentVal.data))
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

func (rb *ReceiveBuffer) GetSndAck() *Ack {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if len(rb.ackList) == 0 {
		return nil
	}

	ack := rb.ackList[0]
	rb.ackList = rb.ackList[1:]
	return ack
}
