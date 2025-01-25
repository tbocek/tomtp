package tomtp

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestInsert(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)

	// Basic insert
	n, err := sb.Insert(1, []byte("test"))
	assert.NoError(err)
	assert.Equal(4, n)

	// Verify stream created correctly
	stream := sb.streams.Get(1).Value
	assert.Equal([]byte("test"), stream.data)
	assert.Equal(uint64(4), stream.unsentOffset)
	assert.Equal(uint64(0), stream.sentOffset)
	assert.Equal(uint64(0), stream.bias)

	// Test capacity limit
	sb = NewSendBuffer(3)
	n, err = sb.Insert(1, []byte("test"))
	assert.Equal(3, n)

	n, err = sb.Insert(1, []byte("test"))
	assert.Equal(ErrBufferFull, err)
	assert.Equal(0, n)

	// Test 48-bit wrapping
	sb = NewSendBuffer(1000)
	stream = NewStreamBuffer()
	stream.unsentOffset = MaxUint48 - 2
	sb.streams.Put(1, stream)
	n, err = sb.Insert(1, []byte("test"))
	assert.NoError(err)
	assert.Equal(4, n)
	assert.Equal(uint64(2), stream.unsentOffset)
	assert.Equal(uint64(0), stream.sentOffset)
}

func TestReadyToSend(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)

	// Insert data
	sb.Insert(1, []byte("test1"))
	sb.Insert(2, []byte("test2"))

	// Basic send
	streamId, offset, data, err := sb.ReadyToSend(10, 100)
	assert.NoError(err)
	assert.Equal(uint32(1), streamId)
	assert.Equal(uint64(0), offset)
	assert.Equal([]byte("test1"), data)

	// Verify range tracking
	stream := sb.streams.Get(1).Value
	rangePair := stream.dataInFlightMap.Oldest()
	assert.NotNil(rangePair)
	assert.Equal(uint64(5)<<48, rangePair.Key&(uint64(0xFFFF)<<48))
	assert.Equal(uint64(100), rangePair.Value.Value)

	sb.ReadyToSend(10, 100)

	// Test MTU limiting
	sb.Insert(3, []byte("toolongdata"))
	streamId, offset, data, err = sb.ReadyToSend(4, 100)
	assert.NoError(err)
	assert.Equal(uint32(3), streamId)
	assert.Equal(uint64(0), offset)
	assert.Equal([]byte("tool"), data)

	// Test round-robin
	streamId, _, _, err = sb.ReadyToSend(10, 100)
	assert.NoError(err)
	assert.Equal(uint32(3), streamId)
}

func TestReadyToRetransmit(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)

	// Setup test data
	sb.Insert(1, []byte("test1"))
	sb.Insert(2, []byte("test2"))
	sb.ReadyToSend(10, 100)
	sb.ReadyToSend(10, 100)

	// Test basic retransmit
	streamId, offset, data, err := sb.ReadyToRetransmit(10, 50, 200)
	assert.NoError(err)
	assert.Equal(uint32(1), streamId)
	assert.Equal(uint64(0), offset)
	assert.Equal([]byte("test1"), data)

	streamId, offset, data, err = sb.ReadyToRetransmit(10, 100, 200)
	assert.Nil(data)

	streamId, offset, data, err = sb.ReadyToRetransmit(10, 99, 200)
	assert.NoError(err)
	assert.Equal(uint32(2), streamId)
	assert.Equal(uint64(0), offset)
	assert.Equal([]byte("test2"), data)

	// Test MTU split
	sb = NewSendBuffer(1000)
	sb.Insert(1, []byte("testdata"))
	sb.ReadyToSend(8, 100)

	streamId, offset, data, err = sb.ReadyToRetransmit(4, 50, 200)
	assert.NoError(err)
	assert.Equal(uint32(1), streamId)
	assert.Equal(uint64(0), offset)
	assert.Equal([]byte("test"), data)

	// Verify range split
	stream := sb.streams.Get(1).Value
	assert.Equal(3, stream.dataInFlightMap.Size())
}

func TestAcknowledgeRangeBasic(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)
	sb.Insert(1, []byte("testdata"))
	sb.ReadyToSend(4, 100)
	assert.True(sb.AcknowledgeRange(1, 0, 4))
	stream := sb.getStream(1)
	assert.Equal(4, len(stream.data))
	assert.Equal(uint64(4), stream.bias)
}

func TestAcknowledgeRangeNonExistentStream(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)
	assert.False(sb.AcknowledgeRange(1, 0, 4))
}

func TestAcknowledgeRangeNonExistentRange(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)
	stream := NewStreamBuffer()
	sb.streams.Put(1, stream)
	assert.False(sb.AcknowledgeRange(1, 0, 4))
}

func TestAcknowledgeRangeBoundary(t *testing.T) {
	assert := require.New(t)
	sb := NewSendBuffer(1000)
	stream := NewStreamBuffer()
	sb.streams.Put(1, stream)

	maxOffset := uint64((1 << 48) - 1)
	stream.dataInFlightMap.Put(maxOffset|(uint64(10)<<48), NewNode[uint64, uint64](maxOffset|(uint64(10)<<48), 123))

	assert.True(sb.AcknowledgeRange(1, maxOffset, 10))
	assert.Equal(0, stream.dataInFlightMap.Size())
}

func TestSendBufferIntegration(t *testing.T) {
	assert := require.New(t)

	t.Run("edge cases with varying MTU and data sizes", func(t *testing.T) {
		sb := NewSendBuffer(1000)

		// Test case 1: Insert data near MaxUint48 boundary
		stream1Data := make([]byte, 100)
		sb.Insert(1, stream1Data)
		stream := sb.streams.Get(1).Value
		stream.unsentOffset = MaxUint48 - 50

		// Insert data that will wrap around
		wrapData := make([]byte, 100)
		n, err := sb.Insert(1, wrapData)
		assert.NoError(err)
		assert.Equal(100, n)
		assert.Equal(uint64(50), stream.unsentOffset)

		// Test case 2: Multiple MTU sizes for ReadyToSend
		streamId, _, data, err := sb.ReadyToSend(30, 100)
		assert.NoError(err)
		assert.Equal(uint32(1), streamId)
		assert.Equal(30, len(data))

		// Smaller MTU
		streamId, _, data, err = sb.ReadyToSend(20, 200)
		assert.NoError(err)
		assert.Equal(20, len(data))

		// Test case 3: Retransmission with MTU changes
		// First send with large MTU
		sb = NewSendBuffer(1000)
		sb.Insert(1, []byte("thisislongdataforretransmission"))
		streamId, _, _, err = sb.ReadyToSend(30, 100)
		assert.NoError(err)

		// Retransmit with smaller MTU
		streamId, _, data, err = sb.ReadyToRetransmit(10, 50, 200)
		assert.NoError(err)
		assert.Equal(uint32(1), streamId)
		assert.Equal(10, len(data))

		// Test case 4: Out of order acknowledgments
		sb = NewSendBuffer(1000)
		testData := []byte("testdatafortestingacks")
		sb.Insert(1, testData)

		// Send in chunks
		sb.ReadyToSend(5, 100) // "testd"
		sb.ReadyToSend(5, 100) // "atafo"
		sb.ReadyToSend(5, 100) // "rtest"

		// Acknowledge in reverse order
		assert.True(sb.AcknowledgeRange(1, 10, 5)) // "rtest"
		assert.True(sb.AcknowledgeRange(1, 5, 5))  // "atafo"
		assert.True(sb.AcknowledgeRange(1, 0, 5))  // "testd"

		stream = sb.streams.Get(1).Value
		assert.Equal(uint64(15), stream.bias)

		// Test case 5: Mixed operations with multiple streams
		sb = NewSendBuffer(1000)

		// Insert into multiple streams
		sb.Insert(1, []byte("stream1data"))
		sb.Insert(2, []byte("stream2data"))
		sb.Insert(3, []byte("stream3data"))

		// Send from different streams with varying MTUs
		_, _, data1, _ := sb.ReadyToSend(5, 100)
		_, _, data2, _ := sb.ReadyToSend(7, 100)
		_, _, data3, _ := sb.ReadyToSend(4, 100)

		assert.Equal(5, len(data1))
		assert.Equal(7, len(data2))
		assert.Equal(4, len(data3))

		// Retransmit with different MTUs
		_, _, retrans1, _ := sb.ReadyToRetransmit(3, 50, 200)
		assert.Equal(3, len(retrans1))

		// Test case 6: Edge case - acknowledge empty range
		assert.False(sb.AcknowledgeRange(1, 0, 0))

		// Test case 7: Complex out-of-order acknowledgments with gaps
		sb = NewSendBuffer(1000)
		sb.Insert(1, []byte("abcdefghijklmnopqrstuvwxyz"))

		// Send in multiple chunks
		sb.ReadyToSend(5, 100) // "abcde"
		sb.ReadyToSend(5, 100) // "fghij"
		sb.ReadyToSend(5, 100) // "klmno"
		sb.ReadyToSend(5, 100) // "pqrst"
		sb.ReadyToSend(5, 100) // "uvwxy"

		// Acknowledge with gaps: 2,4,1,5,3
		assert.True(sb.AcknowledgeRange(1, 5, 5))  // "fghij"
		assert.True(sb.AcknowledgeRange(1, 15, 5)) // "pqrst"
		assert.True(sb.AcknowledgeRange(1, 0, 5))  // "abcde"
		assert.True(sb.AcknowledgeRange(1, 20, 5)) // "uvwxy"
		assert.True(sb.AcknowledgeRange(1, 10, 5)) // "klmno"

		// Test case 8: Out-of-order retransmissions with varying MTUs
		sb = NewSendBuffer(1000)
		sb.Insert(1, []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))

		// Initial send with MTU 10
		sb.ReadyToSend(10, 100) // "ABCDEFGHIJ"
		sb.ReadyToSend(10, 100) // "KLMNOPQRST"
		sb.ReadyToSend(6, 100)  // "UVWXYZ"

		// Retransmit first chunk with larger MTU
		_, _, retrans1, _ = sb.ReadyToRetransmit(10, 50, 200)
		assert.Equal(10, len(retrans1))
		assert.Equal("ABCDEFGHIJ", string(retrans1))

		// Retransmit middle chunk first with smaller MTU
		_, _, retrans2, _ := sb.ReadyToRetransmit(5, 50, 200) // Should split "KLMNOPQRST"
		assert.Equal(5, len(retrans2))
		assert.Equal("KLMNO", string(retrans2))

		// Retransmit remaining part of middle chunk
		_, _, retrans3, _ := sb.ReadyToRetransmit(5, 50, 200)
		assert.Equal(5, len(retrans3))
		assert.Equal("PQRST", string(retrans3))

		// Retransmit remaining part of middle chunk
		_, _, retrans4, _ := sb.ReadyToRetransmit(5, 50, 300)
		assert.Equal(5, len(retrans4))
		assert.Equal("UVWXY", string(retrans4))

		// Test case 9: Edge case - maximum MTU
		sb = NewSendBuffer(1000)
		sb.Insert(1, make([]byte, 65535))
		_, _, maxMtuData, _ := sb.ReadyToSend(65535, 100)
		assert.Equal(1000, len(maxMtuData))
	})
}

func getOffsetAndLength(k uint64) (uint64, uint16) {
	return k & ((1 << 48) - 1), uint16(k >> 48)
}
