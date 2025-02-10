package tomtp

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestInsert(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)
	ctx := context.Background()

	// Basic insert
	_, err := sb.InsertBlocking(ctx, 1, []byte("test"))
	assert.Nil(err)

	// Verify stream created correctly
	streamPair := sb.streams.Get(1)
	assert.NotNil(streamPair)
	stream := streamPair.value
	assert.Equal([]byte("test"), stream.dataToSend)
	assert.Equal(uint64(4), stream.unsentOffset)
	assert.Equal(uint64(0), stream.sentOffset)
	assert.Equal(uint64(0), stream.bias)

	// Test capacity limit
	sb = NewSendBuffer(3)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond) // Timeout
	defer cancel()

	_, err = sb.InsertBlocking(ctx, 1, []byte("test"))
	assert.Error(err)
	assert.Equal(context.DeadlineExceeded, err)

	// Test 48-bit wrapping (using MaxUint64 as uint48 in go doesn't exist)
	sb = NewSendBuffer(1000)
	stream = NewStreamBuffer()
	stream.unsentOffset = math.MaxUint64 - 2
	sb.streams.Put(1, stream)
	_, err = sb.InsertBlocking(context.Background(), 1, []byte("test"))
	assert.Nil(err) // Should succeed now

	streamPair = sb.streams.Get(1)
	assert.NotNil(streamPair)
	stream = streamPair.value

	//assert.Equal(uint64(math.MaxUint64 + 2), stream.unsentOffset) // Rollover will occur. Because we are using unit64
	assert.Equal(uint64(1), stream.unsentOffset) // Rollover will occur. Because we are using unit64
	assert.Equal(uint64(0), stream.sentOffset)
}

func TestReadyToSend(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)
	ctx := context.Background()
	nowMillis2 := uint64(100)

	// Insert data
	sb.InsertBlocking(ctx, 1, []byte("test1"))
	sb.InsertBlocking(ctx, 2, []byte("test2"))

	// Basic send
	data := sb.ReadyToSend(1, 10, nowMillis2)
	assert.Equal([]byte("test1"), data)

	// Verify range tracking
	streamPair := sb.streams.Get(1)
	assert.NotNil(streamPair)
	stream := streamPair.value

	rangePair := stream.dataInFlightMap.Oldest()
	assert.NotNil(rangePair)
	assert.Equal(uint16(5), rangePair.key.length())
	assert.Equal(nowMillis2, rangePair.value.value)

	sb.ReadyToSend(1, 10, nowMillis2)

	// Test MTU limiting
	sb.InsertBlocking(ctx, 3, []byte("toolongdata"))
	data = sb.ReadyToSend(3, 4, nowMillis2)
	assert.Equal([]byte("tool"), data)

	// test no data available
	data = sb.ReadyToSend(4, 10, nowMillis2)
	assert.Nil(data)
}

func TestReadyToRetransmit(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)
	ctx := context.Background()
	//nowMillis := uint64(200)

	// Setup test data
	sb.InsertBlocking(ctx, 1, []byte("test1"))
	sb.InsertBlocking(ctx, 2, []byte("test2"))

	sb.ReadyToSend(1, 10, 100) // Initial send at time 100
	sb.ReadyToSend(2, 10, 100) // Initial send at time 100

	// Test basic retransmit
	data := sb.ReadyToRetransmit(1, 10, 50, 200) // RTO = 50, now = 200.  200-100 > 50
	assert.Equal([]byte("test1"), data)

	data = sb.ReadyToRetransmit(2, 10, 100, 200) //RTO = 100, now = 200. 200-100 = 100, thus ok
	assert.Nil(data)

	data = sb.ReadyToRetransmit(1, 10, 99, 300) // RTO = 99, now = 200. 200-100 > 99
	assert.Equal([]byte("test1"), data)

	// Test MTU split
	sb = NewSendBuffer(1000)
	sb.InsertBlocking(ctx, 1, []byte("testdata"))
	sb.ReadyToSend(1, 100, 100) // Initial send

	data = sb.ReadyToRetransmit(1, 4, 99, 200)
	assert.Equal([]byte("test"), data)

	// Verify range split
	streamPair := sb.streams.Get(1)
	assert.NotNil(streamPair)
	stream := streamPair.value
	assert.Equal(3, stream.dataInFlightMap.Size())
	node := stream.dataInFlightMap.Oldest()
	assert.Equal(uint16(4), node.key.length())
	assert.Equal(uint64(4), node.key.offset())
}

func TestAcknowledgeRangeBasic(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)
	ctx := context.Background()
	sb.InsertBlocking(ctx, 1, []byte("testdata"))
	sb.ReadyToSend(1, 4, 100)
	streamPair := sb.streams.Get(1)
	assert.NotNil(streamPair)
	stream := streamPair.value
	assert.Equal(uint64(100), sb.AcknowledgeRange(1, 0, 4))
	assert.Equal(4, len(stream.dataToSend))
	assert.Equal(uint64(4), stream.bias)
}

func TestAcknowledgeRangeNonExistentStream(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)
	assert.Equal(uint64(0), sb.AcknowledgeRange(1, 0, 4))
}

func TestAcknowledgeRangeNonExistentRange(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)
	stream := NewStreamBuffer()
	sb.streams.Put(1, stream)
	assert.Equal(uint64(0), sb.AcknowledgeRange(1, 0, 4))
}
