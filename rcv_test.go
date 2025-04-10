package tomtp

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestReceiveBuffer_SingleSegment(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 0, []byte("data"))
	assert.Equal(t, RcvInsertOk, status)

	offset, data, err := rb.RemoveOldestInOrder(1)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("data"), data)

	// Verify empty after reading
	_, data, err = rb.RemoveOldestInOrder(1)
	require.Error(t, err)
	require.Empty(t, data)
}

func TestReceiveBuffer_DuplicateSegment(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 0, []byte("data"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 0, []byte("data"))
	assert.Equal(t, RcvInsertDuplicate, status)

	offset, data, err := rb.RemoveOldestInOrder(1)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("data"), data)
}

func TestReceiveBuffer_GapBetweenSegments(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 10, []byte("later"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 0, []byte("early"))
	assert.Equal(t, RcvInsertOk, status)

	// Should get early segment first
	offset, data, err := rb.RemoveOldestInOrder(1)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("early"), data)

	// Then later segment
	offset, data, err = rb.RemoveOldestInOrder(1)
	require.Error(t, err)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, 0, len(data))
}

func TestReceiveBuffer_MultipleStreams(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert segments from different streams
	status := rb.Insert(1, 0, []byte("stream1-first"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(2, 0, []byte("stream2-first"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 13, []byte("stream1-second"))
	assert.Equal(t, RcvInsertOk, status)

	// Read from stream 1
	offset, data, err := rb.RemoveOldestInOrder(1)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("stream1-first"), data)

	// Read from stream 2
	offset, data, err = rb.RemoveOldestInOrder(2)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("stream2-first"), data)

	// Read second segment from stream 1
	offset, data, err = rb.RemoveOldestInOrder(1)
	require.NoError(t, err)
	assert.Equal(t, uint64(13), offset)
	assert.Equal(t, []byte("stream1-second"), data)
}

func TestReceiveBuffer_BufferFullExact(t *testing.T) {
	rb := NewReceiveBuffer(4)

	status := rb.Insert(1, 0, []byte("data"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 4, []byte("more"))
	assert.Equal(t, RcvInsertBufferFull, status)

	offset, data, err := rb.RemoveOldestInOrder(1)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("data"), data)
}

func TestReceiveBuffer_RemoveWithHigherOffset(t *testing.T) {
	rb := NewReceiveBuffer(4)

	status := rb.Insert(1, 0, []byte("12345"))
	assert.Equal(t, RcvInsertBufferFull, status)

	offset, data, err := rb.RemoveOldestInOrder(1)
	require.Error(t, err)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, 0, len(data))
}

func TestReceiveBuffer_RemoveWithHigherOffset_EmptyAfterLast(t *testing.T) {
	rb := NewReceiveBuffer(4)

	status := rb.Insert(1, 0, []byte("1"))
	assert.Equal(t, RcvInsertOk, status)

	offset, data, err := rb.RemoveOldestInOrder(1)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("1"), data)

	// Should be empty after reading
	_, data, err = rb.RemoveOldestInOrder(1)
	require.Error(t, err)
	require.Empty(t, data)
}

func TestGetAcks_NoAcks(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	ack := rb.GetAck()
	assert.Nil(t, ack)
}
