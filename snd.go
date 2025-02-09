package tomtp

import (
	"errors"
	"sync"
)

type nowMillis uint64

type packetKey [10]byte

func (p packetKey) offset() uint64 {
	return Uint64(p[:8])
}

func (p packetKey) length() uint16 {
	return Uint16(p[8:])
}

func (p packetKey) less(other packetKey) bool {
	for i := 0; i < 10; i++ {
		if p[i] < other[i] {
			return true
		}
		if p[i] > other[i] {
			return false
		}
	}
	return false
}

func createPacketKey(offset uint64, length uint16) packetKey {
	var p packetKey
	PutUint64(p[:8], offset)
	PutUint16(p[8:], length)
	return p
}

// StreamBuffer represents a single stream's data and metadata
type StreamBuffer struct {
	//here we append the data, after appending, we sent currentOffset.
	//This is necessary, as when data gets acked, we Remove the acked data,
	//which will be in front of the array. Thus, len(data) would not work.
	data []byte
	// based on offset, which is uint48. This is the offset of the data we did not send yet
	unsentOffset uint64
	// based on offset, which is uint48. This is the offset of the data we did send
	sentOffset uint64
	// when data is acked, we Remove the data, however we don't want to update all the offsets, hence this bias
	// TODO: check what happens on an 64bit rollover
	bias uint64
	// inflight data - key is offset, which is uint48, len in 16bit is added to a 64bit key. value is sentTime
	// If MTU changes for inflight packets and need to be resent. The range is split. Example:
	// offset: 500, len/mtu: 50 -> 1 range: 500/50,time
	// retransmit with mtu:20 -> 3 dataInFlightMap: 500/20,time; 520/20,time; 540/10,time
	dataInFlightMap *linkedHashMap[packetKey, *node[packetKey, nowMillis]]
}

type SendBuffer struct {
	streams *linkedHashMap[uint32, *StreamBuffer] // Changed to LinkedHashMap
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
		data:            []byte{},
		dataInFlightMap: newLinkedHashMap[packetKey, *node[packetKey, nowMillis]](),
	}
}

func NewSendBuffer(capacity int) *SendBuffer {
	return &SendBuffer{
		streams:  newLinkedHashMap[uint32, *StreamBuffer](),
		capacity: capacity,
		mu:       &sync.Mutex{},
	}
}

// Insert stores the data in the dataMap
func (sb *SendBuffer) Insert(streamId uint32, data []byte) bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Check capacity
	dataLen := len(data)
	if sb.capacity < sb.totalSize+dataLen {
		return false
	}

	// Get or create stream buffer
	entry := sb.streams.Get(streamId)
	if entry == nil {
		stream := NewStreamBuffer()
		entry = sb.streams.Put(streamId, stream)
	}

	stream := entry.value

	// Store data
	stream.data = append(stream.data, data...)
	stream.unsentOffset = stream.unsentOffset + uint64(dataLen)
	sb.totalSize += dataLen

	return true
}

// ReadyToSend finds unsent data and creates a range entry for tracking
func (sb *SendBuffer) ReadyToSend(mtu uint16, nowMillis2 uint64) (streamId uint32, offset uint64, data []byte, err error) {
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

	startStreamId := streamPair.key
	for {
		stream := streamPair.value
		streamId = streamPair.key

		// Check if there's unsent data, if true, we have unsent data
		if stream.unsentOffset > stream.sentOffset {
			remainingData := stream.unsentOffset - stream.sentOffset

			//the max length we can send
			length := uint16(min(uint64(mtu), remainingData))

			// Pack offset and length into key
			key := createPacketKey(stream.sentOffset, length)

			// Check if range is already tracked
			if stream.dataInFlightMap.Get(key) == nil {
				// Get data slice accounting for bias
				offset = stream.sentOffset - stream.bias
				data = stream.data[offset : offset+uint64(length)]

				// Track range
				stream.dataInFlightMap.Put(key, newNode(key, nowMillis(nowMillis2)))

				// Update tracking
				stream.sentOffset = stream.sentOffset + uint64(length)
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
		if streamPair.key == startStreamId {
			break
		}
	}

	return 0, 0, nil, nil
}

// ReadyToRetransmit finds expired dataInFlightMap that need to be resent
func (sb *SendBuffer) ReadyToRetransmit(mtu uint16, rto uint64, nowMillis2 uint64) (streamId uint32, offset uint64, data []byte) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.streams.Size() == 0 {
		return 0, 0, nil
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

	startStreamId := streamPair.key
	for {
		stream := streamPair.value
		streamId = streamPair.key

		// Check Oldest range first
		dataInFlight := stream.dataInFlightMap.Oldest()
		if dataInFlight != nil {
			sentTime := dataInFlight.value.value
			if !dataInFlight.value.IsShadow() && nowMillis2-uint64(sentTime) > rto {
				// Extract offset and length from key
				rangeOffset := dataInFlight.key.offset()
				rangeLen := dataInFlight.key.length()

				// Get data using bias
				dataOffset := rangeOffset - stream.bias
				data = stream.data[dataOffset : dataOffset+uint64(rangeLen)]

				sb.lastReadToRetransmitStream = streamId
				if rangeLen <= mtu {
					// Remove old range
					stream.dataInFlightMap.Remove(dataInFlight.key)
					// Same MTU - resend entire range
					stream.dataInFlightMap.Put(dataInFlight.key, newNode(dataInFlight.key, nowMillis(nowMillis2)))
					return streamPair.key, dataOffset, data
				} else {
					// Split range due to smaller MTU
					leftKey := createPacketKey(rangeOffset, mtu)
					// Queue remaining data with nxt offset
					remainingOffset := rangeOffset + uint64(mtu)
					remainingLen := rangeLen - mtu
					rightKey := createPacketKey(remainingOffset, remainingLen)

					l, r := dataInFlight.value.Split(leftKey, nowMillis(nowMillis2), rightKey, dataInFlight.value.value)
					oldParentKey := dataInFlight.key
					oldParentValue := dataInFlight.value.value
					n := newNode(r.key, oldParentValue)

					//we return the left, thus we need to reinsert as we have a new send time
					//the right we keep, and Replace it with the old value, so it keeps the send time
					dataInFlight.Replace(r.key, n)
					stream.dataInFlightMap.Put(l.key, newNode(l.key, nowMillis(nowMillis2)))
					stream.dataInFlightMap.Put(oldParentKey, newNode(oldParentKey, nowMillis(nowMillis2)))

					return streamPair.key, dataOffset, data[:mtu]
				}
			}
		}

		streamPair = streamPair.Next()
		if streamPair == nil {
			streamPair = sb.streams.Oldest()
		}
		if streamPair.key == startStreamId {
			break
		}
	}

	return 0, 0, nil
}

// AcknowledgeRange handles acknowledgment of data
func (sb *SendBuffer) AcknowledgeRange(streamId uint32, offset uint64, length uint16) uint64 {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	streamPair := sb.streams.Get(streamId)
	if streamPair == nil {
		return 0
	}
	stream := streamPair.value

	// Remove range key
	key := createPacketKey(offset, length)

	rangePair := stream.dataInFlightMap.Remove(key)
	if rangePair == nil {
		return 0
	}

	firstSentTime := rangePair.value.value

	delKeys := rangePair.value.Remove()
	for _, delKey := range delKeys {
		deletePair := stream.dataInFlightMap.Remove(delKey)
		if deletePair != nil {
			removeSentTime := deletePair.value.value
			if removeSentTime < firstSentTime {
				firstSentTime = removeSentTime
			}
		}
	}

	// If this range starts at our bias point, we can Remove data
	if offset == stream.bias {
		// Check if we have a gap between this ack and nxt range
		nextRange := stream.dataInFlightMap.Oldest()
		if nextRange == nil {
			// No gap, safe to Remove all data
			stream.data = stream.data[stream.sentOffset-stream.bias:]
			stream.bias += stream.sentOffset
			sb.totalSize -= int(stream.sentOffset)
		} else {
			nextOffset := nextRange.key.offset()
			stream.data = stream.data[nextOffset-stream.bias:]
			stream.bias += nextOffset
			sb.totalSize -= int(nextOffset)
		}
	}

	return uint64(firstSentTime)
}
