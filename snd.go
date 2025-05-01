package tomtp

import (
	"errors"
	"log/slog"
	"sync"
	"time"
)

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

type MetaData struct {
	sentMicros int64
	sentNr     int
	msgType    MsgType //we may know this only after running encryption
	offset     uint64
}

func (r *MetaData) less(other *MetaData) bool {
	return r.sentMicros < other.sentMicros
}

func (r *MetaData) eq(other *MetaData) bool {
	return r.sentMicros == other.sentMicros
}

// StreamBuffer represents a single stream's dataToSend and metadata
type StreamBuffer struct {
	// here we append the dataToSend, after appending, we sent currentOffset.
	// This is necessary, as when dataToSend gets acked, we Remove the acked dataToSend,
	// which will be in front of the array. Thus, len(dataToSend) would not work.
	dataToSend []byte
	// this is the offset of the dataToSend we did not send yet
	unsentOffset uint64
	// this is the offset of the dataToSend we did send
	sentOffset uint64
	// when dataToSend is acked, we Remove the dataToSend, however we don't want to update all the offsets, hence this bias
	// TODO: check what happens on an 64bit rollover
	bias uint64
	// inflight dataToSend - key is offset, which is uint48, len in 16bit is added to a 64bit key. value is sentTime
	// If MTU changes for inflight packets and need to be resent. The range is split. Example:
	// offset: 500, len/mtu: 50 -> 1 range: 500/50,time
	// retransmit with mtu:20 -> 3 dataInFlightMap: 500/20,time; 520/20,time; 540/10,time
	dataInFlightMap *skipList[packetKey, *MetaData]
}

type SendBuffer struct {
	streams                    map[uint32]*StreamBuffer // Changed to LinkedHashMap
	lastReadToSendStream       uint32                   //for round-robin, we continue where we left
	lastReadToRetransmitStream uint32
	capacity                   int //len(dataToSend) of all streams cannot become larger than capacity
	totalSize                  int //len(dataToSend) of all streams
	mu                         *sync.Mutex
	capacityAvailable          *sync.Cond
}

func NewStreamBuffer() *StreamBuffer {
	return &StreamBuffer{
		dataToSend: []byte{},
		dataInFlightMap: newSortedHashMap[packetKey, *MetaData](func(a, b packetKey, c, d *MetaData) bool {
			if c.eq(d) {
				return a.less(b)
			}
			return c.less(d)
		}),
	}
}

func NewSendBuffer(capacity int) *SendBuffer {
	mu := &sync.Mutex{}
	capacityAvailable := sync.NewCond(mu)
	return &SendBuffer{
		streams:           make(map[uint32]*StreamBuffer),
		capacity:          capacity,
		mu:                mu,
		capacityAvailable: capacityAvailable,
	}
}

// Insert stores the dataToSend in the dataMap, does not send yet
func (sb *SendBuffer) Insert(streamId uint32, data []byte, rcvWndSize uint64) (int, error) {
	var processedBytes int
	remainingData := data

	for len(remainingData) > 0 {
		sb.mu.Lock()

		// Calculate how much dataToSend we can insert
		remainingCapacitySnd := sb.capacity - sb.totalSize
		if remainingCapacitySnd <= 0 {
			return 0, errors.New("full capacity")
		}

		remainingCapacityRcv := int(rcvWndSize) - sb.totalSize
		if remainingCapacityRcv <= 0 {
			return 0, errors.New("full capacity")
		}

		// Calculate chunk size
		chunkSize := min(len(remainingData), remainingCapacitySnd, remainingCapacityRcv)
		chunk := remainingData[:chunkSize]

		// Get or create stream buffer
		stream := sb.streams[streamId]
		if stream == nil {
			stream = NewStreamBuffer()
			sb.streams[streamId] = stream
		}

		// Store chunk
		stream.dataToSend = append(stream.dataToSend, chunk...)
		stream.unsentOffset = stream.unsentOffset + uint64(chunkSize)
		sb.totalSize += chunkSize

		// Update remaining dataToSend
		remainingData = remainingData[chunkSize:]
		processedBytes += chunkSize

		sb.mu.Unlock()
	}

	return processedBytes, nil
}

// ReadyToSend gets data from dataToSend and creates an entry in dataInFlightMap
func (sb *SendBuffer) ReadyToSend(streamId uint32, maxData uint16, nowMicros int64) (splitData []byte, m *MetaData) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if len(sb.streams) == 0 {
		return nil, nil
	}

	stream := sb.streams[streamId]
	if stream == nil {
		return nil, nil
	}

	// Check if there's unsent dataToSend, if true, we have unsent dataToSend
	if stream.unsentOffset > stream.sentOffset {
		remainingData := stream.unsentOffset - stream.sentOffset

		//the max length we can send
		length := uint16(min(uint64(maxData), remainingData))

		// Pack offset and length into key
		key := createPacketKey(stream.sentOffset, length)

		// Check if range is already tracked
		if stream.dataInFlightMap.Get(key) == nil {
			// Get dataToSend slice accounting for bias
			offset := stream.sentOffset - stream.bias
			splitData = stream.dataToSend[offset : offset+uint64(length)]

			// Track range
			m = &MetaData{sentMicros: nowMicros, sentNr: 1, msgType: -1, offset: stream.sentOffset} //we do not know the msg type yet
			stream.dataInFlightMap.Put(key, m)

			// Update tracking
			stream.sentOffset = stream.sentOffset + uint64(length)
			sb.lastReadToSendStream = streamId

			return splitData, m
		} else {
			panic(errors.New("stream range already sent? should not happen"))
		}
	}

	return nil, nil
}

// ReadyToRetransmit finds expired dataInFlightMap that need to be resent
func (sb *SendBuffer) ReadyToRetransmit(streamId uint32, maxData uint16, rto time.Duration, nowMicros int64) (data []byte, m *MetaData, err error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if len(sb.streams) == 0 {
		return nil, nil, nil
	}

	stream := sb.streams[streamId]
	if stream == nil {
		return nil, nil, nil
	}

	// Check Oldest range first
	dataInFlight := stream.dataInFlightMap.Min()
	if dataInFlight != nil {
		rtoData := dataInFlight.value
		currentRto, err := backoff(rto, rtoData.sentNr)
		if err != nil {
			return nil, nil, err
		}

		slog.Debug("RTO check vars",
			slog.Int64("nowMicros", nowMicros),
			slog.Int64("rtoData.sentMicros", rtoData.sentMicros),
			slog.Int64("currentRto.Microseconds()", currentRto.Microseconds()))

		if nowMicros-rtoData.sentMicros > currentRto.Microseconds() {
			// Extract offset and length from key
			rangeOffset := dataInFlight.key.offset()
			rangeLen := dataInFlight.key.length()

			// Get dataToSend using bias
			dataOffset := rangeOffset - stream.bias
			data = stream.dataToSend[dataOffset : dataOffset+uint64(rangeLen)]

			sb.lastReadToRetransmitStream = streamId
			if rangeLen <= maxData {
				// Remove old range
				stream.dataInFlightMap.Remove(dataInFlight.key)
				// Same MTU - resend entire range
				m := &MetaData{sentMicros: nowMicros, sentNr: rtoData.sentNr + 1, msgType: rtoData.msgType, offset: rangeOffset}
				stream.dataInFlightMap.Put(dataInFlight.key, m)
				return data, m, nil
			} else {
				// Split range due to smaller MTU
				leftKey := createPacketKey(rangeOffset, maxData)
				// Queue remaining dataToSend with nxt offset
				remainingOffset := rangeOffset + uint64(maxData)
				remainingLen := rangeLen - maxData
				rightKey := createPacketKey(remainingOffset, remainingLen)

				// Remove old range
				stream.dataInFlightMap.Remove(dataInFlight.key)
				mLeft := &MetaData{sentMicros: nowMicros, sentNr: rtoData.sentNr + 1, msgType: rtoData.msgType, offset: rangeOffset}
				stream.dataInFlightMap.Put(leftKey, mLeft)
				mRight := &MetaData{sentMicros: rtoData.sentMicros, sentNr: rtoData.sentNr, msgType: rtoData.msgType, offset: remainingOffset}
				stream.dataInFlightMap.Put(rightKey, mRight)

				return data[:maxData], mLeft, nil
			}
		}
	}

	return nil, nil, nil
}

// AcknowledgeRange handles acknowledgment of dataToSend
func (sb *SendBuffer) AcknowledgeRange(ack *Ack, isClose bool) (sentTimeMicros int64) {
	sb.mu.Lock()

	stream := sb.streams[ack.streamId]
	if stream == nil {
		sb.mu.Unlock()
		return 0
	}

	// Remove range key
	key := createPacketKey(ack.offset, ack.len)

	rangePair := stream.dataInFlightMap.Remove(key)
	if rangePair == nil {
		sb.mu.Unlock()
		return 0
	}

	sentTimeMicros = rangePair.value.sentMicros

	// If this range starts at our bias point, we can Remove dataToSend
	if ack.offset == stream.bias {
		// Check if we have a gap between this ack and nxt range
		nextRange := stream.dataInFlightMap.Min()
		if nextRange == nil {
			// No gap, safe to Remove all dataToSend
			stream.dataToSend = stream.dataToSend[stream.sentOffset-stream.bias:]
			sb.totalSize -= int(stream.sentOffset - stream.bias)
			stream.bias += stream.sentOffset - stream.bias
		} else {
			nextOffset := nextRange.key.offset()
			stream.dataToSend = stream.dataToSend[nextOffset-stream.bias:]
			stream.bias += nextOffset
			sb.totalSize -= int(nextOffset)
		}
		// Broadcast capacity availability
		sb.capacityAvailable.Broadcast()
	}
	sb.mu.Unlock()
	return sentTimeMicros
}

// Size returns the total size of data in the send buffer
func (sb *SendBuffer) Size() int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.totalSize
}

func (sb *SendBuffer) HasCapacity() bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	remainingCapacity := sb.capacity - sb.totalSize
	return remainingCapacity > 0
}
