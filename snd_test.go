package tomtp

import (
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func TestInsert(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)

	// Basic insert
	_, status := sb.Insert(1, []byte("test"), math.MaxInt)
	assert.Equal(InsertStatusOk, status)

	// Verify stream created correctly
	stream := sb.streams[1]

	assert.Equal([]byte("test"), stream.dataToSend)
	assert.Equal(uint64(4), stream.unsentOffset)
	assert.Equal(uint64(0), stream.sentOffset)
	assert.Equal(uint64(0), stream.bias)

	// Test capacity limit
	sb = NewSendBuffer(3)
	nr, status := sb.Insert(1, []byte("test"), math.MaxInt)
	assert.Equal(InsertStatusOk, status)
	assert.Equal(3, nr)

	// Test 48-bit wrapping (using MaxUint64 as uint48 in go doesn't exist)
	sb = NewSendBuffer(1000)
	stream = NewStreamBuffer()
	stream.unsentOffset = math.MaxUint64 - 2
	sb.streams[1] = stream
	_, status = sb.Insert(1, []byte("test"), math.MaxInt)
	assert.Equal(InsertStatusOk, status) // Should succeed now

	stream = sb.streams[1]
	//assert.Equal(uint64(math.MaxUint64 + 2), stream.unsentOffset) // Rollover will occur. Because we are using unit64
	assert.Equal(uint64(1), stream.unsentOffset) // Rollover will occur. Because we are using unit64
	assert.Equal(uint64(0), stream.sentOffset)
}

func TestReadyToSend(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)
	nowMillis2 := uint64(100)

	// Insert data
	sb.Insert(1, []byte("test1"), math.MaxInt)
	sb.Insert(2, []byte("test2"), math.MaxInt)

	// Basic send
	data, _ := sb.ReadyToSend(1, 10, nowMillis2)
	assert.Equal([]byte("test1"), data)

	// Verify range tracking
	stream := sb.streams[1]

	rangePair := stream.dataInFlightMap.Min()
	assert.NotNil(rangePair)
	assert.Equal(uint16(5), rangePair.key.length())
	assert.Equal(nowMillis2, rangePair.value.sentMicros)

	sb.ReadyToSend(1, 10, nowMillis2)

	// Test MTU limiting
	sb.Insert(3, []byte("toolongdata"), math.MaxInt)
	data, _ = sb.ReadyToSend(3, 4, nowMillis2)
	assert.Equal([]byte("tool"), data)

	// test no data available
	data, _ = sb.ReadyToSend(4, 10, nowMillis2)
	assert.Nil(data)
}

func TestReadyToRetransmit(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)

	// Setup test data
	sb.Insert(1, []byte("test1"), math.MaxInt)
	sb.Insert(2, []byte("test2"), math.MaxInt)

	sb.ReadyToSend(1, 10, 100) // Initial send at time 100
	sb.ReadyToSend(2, 10, 100) // Initial send at time 100

	// Test basic retransmit
	data, _, err := sb.ReadyToRetransmit(1, 10, 50, 200) // RTO = 50, now = 200.  200-100 > 50
	assert.Nil(err)
	assert.Equal([]byte("test1"), data)

	data, _, err = sb.ReadyToRetransmit(2, 10, 100, 200) //RTO = 100, now = 200. 200-100 = 100, thus ok
	assert.Nil(err)
	assert.Nil(data)

	data, _, err = sb.ReadyToRetransmit(1, 10, 99, 399) // RTO = 99, now = 200. 200-100 > 99
	assert.Nil(err)
	assert.Equal([]byte("test1"), data)

	// Test MTU split
	sb = NewSendBuffer(1000)
	sb.Insert(1, []byte("testdata"), math.MaxInt)
	sb.ReadyToSend(1, 100, 100) // Initial send

	data, _, err = sb.ReadyToRetransmit(1, 4, 99, 200)
	assert.Nil(err)
	assert.Equal([]byte("test"), data)

	// Verify range split
	stream := sb.streams[1]

	assert.Equal(2, stream.dataInFlightMap.Size())
	node := stream.dataInFlightMap.Min()
	assert.Equal(uint16(4), node.key.length())
	assert.Equal(uint64(4), node.key.offset())
}

func TestAcknowledgeRangeBasic(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)
	sb.Insert(1, []byte("testdata"), math.MaxInt)
	sb.ReadyToSend(1, 4, 100)
	stream := sb.streams[1]

	_, time := sb.AcknowledgeRange(&Ack{
		streamId: 1,
		offset:   0,
		len:      4,
	})
	assert.Equal(uint64(100), time)
	assert.Equal(4, len(stream.dataToSend))
	assert.Equal(uint64(4), stream.bias)
}

func TestAcknowledgeRangeNonExistentStream(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)
	_, time := sb.AcknowledgeRange(&Ack{
		streamId: 1,
		offset:   0,
		len:      4,
	})
	assert.Equal(uint64(0), time)
}

func TestAcknowledgeRangeNonExistentRange(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)
	stream := NewStreamBuffer()
	sb.streams[1] = stream
	_, time := sb.AcknowledgeRange(&Ack{
		streamId: 1,
		offset:   0,
		len:      4,
	})
	assert.Equal(uint64(0), time)
}
