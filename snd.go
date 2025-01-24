package tomtp

import (
	"errors"
	"sync"
)

var ErrBufferFull = errors.New("buffer is full")

type StreamBuffer struct {
	//here we append the data, after appending, we sent currentOffset.
	//This is necessary, as when data gets acked, we remove the acked data,
	//which will be in front of the array. Thus, len(data) would not work.
	data []byte
	// based on offset, which is uint48. This is the offset of the data we did not send yet
	unsentOffset uint64
	// based on offset, which is uint48. This is the offset of the data we did send
	sentOffset uint64
	// when data is acked, we remove the data, however we dont want to update all the offsets, hence this bias
	bias uint64
	// inflight data - key is offset, which is uint48, len in 16bit is added to a 64bit key. Value is sentTime
	// If MTU changes for inflight packets and need to be resent. The range is split. Example:
	// offset: 500, len/mtu: 50 -> 1 range: 500/50,time
	// retransmit with mtu:20 -> 3 ranges: 500/20,time; 520/20,time; 540/10,time
	ranges *LinkedHashMap[uint64, *Node[uint64, uint64]]
}

type SendBuffer struct {
	streams *LinkedHashMap[uint32, *StreamBuffer] // Changed to LinkedHashMap
	//for round-robin, make sure we continue where we left
	lastReadToSendStream       uint32
	lastReadToRetransmitStream uint32
	//len(data) of all streams cannot become larger than capacity. With this we can throttle sending
	capacity int
	//len(data) of all streams
	totalSize int
	mu        *sync.Mutex
}

func NewStreamBuffer() *StreamBuffer {
	return &StreamBuffer{
		data:   []byte{},
		ranges: NewLinkedHashMap[uint64, *Node[uint64, uint64]](),
	}
}

func NewStreamBufferWithData(data []byte) *StreamBuffer {
	return &StreamBuffer{
		data:   data,
		ranges: NewLinkedHashMap[uint64, *Node[uint64, uint64]](),
	}
}

func NewSendBuffer(capacity int) *SendBuffer {
	return &SendBuffer{
		streams:  NewLinkedHashMap[uint32, *StreamBuffer](),
		capacity: capacity,
		mu:       &sync.Mutex{},
	}
}

func (sb *SendBuffer) getStream(streamId uint32) *StreamBuffer {
	return sb.streams.Get(streamId).Value
}

// Insert stores the data in the dataMap
func (sb *SendBuffer) Insert(streamId uint32, data []byte) (n int, err error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Check capacity
	remainingCapacity := sb.capacity - sb.totalSize
	if remainingCapacity <= 0 {
		return 0, ErrBufferFull
	}
	n = min(remainingCapacity, len(data))

	// Get or create stream buffer
	entry := sb.streams.Get(streamId)
	if entry == nil {
		stream := NewStreamBuffer()
		sb.streams.Put(streamId, stream)
		entry = sb.streams.Get(streamId)
	}

	stream := entry.Value

	// Store data
	stream.data = append(stream.data, data[:n]...)
	stream.unsentOffset = (stream.unsentOffset + uint64(n)) % MaxUint48
	sb.totalSize += len(data)

	return n, nil
}

// ReadyToSend finds unsent data and creates a range entry for tracking
func (sb *SendBuffer) ReadyToSend(mtu uint16, nowMillis uint64) (streamId uint32, offset uint64, data []byte, err error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.streams.Size() == 0 {
		return 0, 0, nil, nil
	}

	streamPair := sb.streams.Get(sb.lastReadToSendStream)
	if streamPair == nil {
		streamPair = sb.streams.Oldest()
	} else {
		nextStreamPair := streamPair.Next()
		if nextStreamPair == nil {
			streamPair = sb.streams.Oldest()
		} else {
			streamPair = nextStreamPair
		}

	}

	startStreamId := streamPair.Key
	for {
		stream := streamPair.Value
		streamId = streamPair.Key

		// Check if there's unsent data, if true, we have unsent data
		if stream.unsentOffset > stream.sentOffset {
			remainingData := stream.unsentOffset - stream.sentOffset

			//the max length we can send
			length := uint16(min(uint64(mtu), remainingData))

			// Pack offset and length into key
			key := stream.sentOffset | (uint64(length) << 48)

			// Check if range is already tracked
			if stream.ranges.Get(key) == nil {
				// Get data slice accounting for bias
				offset = stream.sentOffset - stream.bias
				data = stream.data[offset : offset+uint64(length)]

				// Track range
				stream.ranges.Put(key, NewNode(key, nowMillis))

				// Update tracking
				stream.sentOffset = stream.sentOffset + uint64(length)%MaxUint48
				sb.lastReadToSendStream = streamId

				return streamId, offset, data, nil
			} else {
				panic(errors.New("stream range already sent? should not happen"))
			}
		}

		streamPair = streamPair.Next()
		if streamPair == nil {
			streamPair = sb.streams.Oldest()
		}
		if streamPair.Key == startStreamId {
			break
		}
	}

	return 0, 0, nil, nil
}

// ReadyToRetransmit finds expired ranges that need to be resent
func (sb *SendBuffer) ReadyToRetransmit(mtu uint16, rto uint64, nowMillis uint64) (streamId uint32, offset uint64, data []byte, err error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.streams.Size() == 0 {
		return 0, 0, nil, nil
	}

	streamPair := sb.streams.Get(sb.lastReadToSendStream)
	if streamPair == nil {
		streamPair = sb.streams.Oldest()
	} else {
		nextStreamPair := streamPair.Next()
		if nextStreamPair == nil {
			streamPair = sb.streams.Oldest()
		} else {
			streamPair = nextStreamPair
		}

	}

	startStreamId := streamPair.Key
	for {
		stream := streamPair.Value
		streamId = streamPair.Key

		// Check oldest range first
		rangePair := stream.ranges.Oldest()
		if rangePair != nil {
			sentTime := rangePair.Value.Value
			if !rangePair.Value.IsShadow() && nowMillis-sentTime > rto {
				// Extract offset and length from key
				rangeOffset := rangePair.Key & ((1 << 48) - 1)
				rangeLen := uint16(rangePair.Key >> 48)

				// Get data using bias
				dataOffset := rangeOffset - stream.bias
				data = stream.data[dataOffset : dataOffset+uint64(rangeLen)]

				sb.lastReadToRetransmitStream = streamId
				if rangeLen <= mtu {
					// Remove old range
					stream.ranges.Remove(rangePair.Key)
					// Same MTU - resend entire range
					stream.ranges.Put(rangePair.Key, NewNode(rangePair.Key, nowMillis))
					return streamPair.Key, dataOffset, data, nil
				} else {
					// Split range due to smaller MTU
					leftKey := rangeOffset | (uint64(mtu) << 48)
					// Queue remaining data with next offset
					remainingOffset := rangeOffset + uint64(mtu)%MaxUint48
					remainingLen := rangeLen - mtu
					rightKey := remainingOffset | (uint64(remainingLen) << 48)

					l, r := rangePair.Value.Split(leftKey, nowMillis, rightKey, rangePair.Value.Value)
					oldParentKey := rangePair.Key
					oldParentValue := rangePair.Value

					rangePair.Replace(NewNode(r.Key, oldParentValue))
					stream.ranges.Put(l.Key, NewNode(l.Key, nowMillis))
					stream.ranges.Put(oldParentKey, NewNode(oldParentKey, nowMillis))

					return streamPair.Key, dataOffset, data[:mtu], nil
				}
			}
		}

		streamPair = streamPair.Next()
		if streamPair == nil {
			streamPair = sb.streams.Oldest()
		}
		if streamPair.Key == startStreamId {
			break
		}
	}

	return 0, 0, nil, nil
}

// AcknowledgeRange handles acknowledgment of data
func (sb *SendBuffer) AcknowledgeRange(streamId uint32, offset uint64, length uint16) (isRemoved bool) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	streamPair := sb.streams.Get(streamId)
	if streamPair == nil {
		return false
	}
	stream := streamPair.Value

	// Remove range key
	key := offset | (uint64(length) << 48)

	rangePair := stream.ranges.Remove(key)
	if rangePair == nil {
		return false
	}

	delKeys := rangePair.Value.Remove()
	for _, delKey := range delKeys {
		stream.ranges.Remove(delKey)
	}

	// If this range starts at our bias point, we can remove data
	if offset == stream.bias {
		// Check if we have a gap between this ack and next range
		nextRange := stream.ranges.Oldest()
		if nextRange == nil {
			// No gap, safe to remove all data
			stream.data = stream.data[stream.sentOffset-stream.bias:]
			stream.bias += stream.sentOffset
			sb.totalSize -= int(stream.sentOffset)
		} else {
			nextOffset := nextRange.Key & ((1 << 48) - 1)
			stream.data = stream.data[nextOffset-stream.bias:]
			stream.bias += nextOffset
			sb.totalSize -= int(nextOffset)
		}
	}

	return true
}
