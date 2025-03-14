package tomtp

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestReceiveBuffer_SingleSegment(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	status := rb.Insert(1, 0, []byte("data"))
	assert.Equal(t, RcvInsertOk, status)

	offset, data, err := rb.RemoveOldestInOrderBlocking(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("data"), data)

	// Verify empty after reading
	_, data, err = rb.RemoveOldestInOrderBlocking(ctx, 1)
	require.Error(t, err)
	require.Empty(t, data)
}

func TestReceiveBuffer_DuplicateSegment(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	status := rb.Insert(1, 0, []byte("data"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 0, []byte("data"))
	assert.Equal(t, RcvInsertDuplicate, status)

	offset, data, err := rb.RemoveOldestInOrderBlocking(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("data"), data)
}

func TestReceiveBuffer_GapBetweenSegments(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	status := rb.Insert(1, 10, []byte("later"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 0, []byte("early"))
	assert.Equal(t, RcvInsertOk, status)

	// Should get early segment first
	offset, data, err := rb.RemoveOldestInOrderBlocking(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("early"), data)

	// Then later segment
	offset, data, err = rb.RemoveOldestInOrderBlocking(ctx, 1)
	require.Error(t, err)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, 0, len(data))
}

func TestReceiveBuffer_MultipleStreams(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Insert segments from different streams
	status := rb.Insert(1, 0, []byte("stream1-first"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(2, 0, []byte("stream2-first"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 13, []byte("stream1-second"))
	assert.Equal(t, RcvInsertOk, status)

	// Read from stream 1
	offset, data, err := rb.RemoveOldestInOrderBlocking(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("stream1-first"), data)

	// Read from stream 2
	offset, data, err = rb.RemoveOldestInOrderBlocking(ctx, 2)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("stream2-first"), data)

	// Read second segment from stream 1
	offset, data, err = rb.RemoveOldestInOrderBlocking(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, uint64(13), offset)
	assert.Equal(t, []byte("stream1-second"), data)
}

func TestReceiveBuffer_BufferFullExact(t *testing.T) {
	rb := NewReceiveBuffer(4)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	status := rb.Insert(1, 0, []byte("data"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 4, []byte("more"))
	assert.Equal(t, RcvInsertBufferFull, status)

	offset, data, err := rb.RemoveOldestInOrderBlocking(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("data"), data)
}

func TestReceiveBuffer_RemoveWithHigherOffset(t *testing.T) {
	rb := NewReceiveBuffer(4)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	status := rb.Insert(1, 0, []byte("12345"))
	assert.Equal(t, RcvInsertBufferFull, status)

	offset, data, err := rb.RemoveOldestInOrderBlocking(ctx, 1)
	require.Error(t, err)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, 0, len(data))
}

func TestReceiveBuffer_RemoveWithHigherOffset_EmptyAfterLast(t *testing.T) {
	rb := NewReceiveBuffer(4)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	status := rb.Insert(1, 0, []byte("1"))
	assert.Equal(t, RcvInsertOk, status)

	offset, data, err := rb.RemoveOldestInOrderBlocking(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("1"), data)

	// Should be empty after reading
	_, data, err = rb.RemoveOldestInOrderBlocking(ctx, 1)
	require.Error(t, err)
	require.Empty(t, data)
}

func TestGetAcks_NoAcks(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	acks := rb.GetAcks()
	assert.Nil(t, acks)
}

func TestGetAcks_SingleBatch(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	for i := 0; i < 10; i++ {
		rb.Insert(1, uint64(i*10), []byte("data"))
	}

	acks := rb.GetAcks()
	assert.Equal(t, 10, len(acks))

	acks = rb.GetAcks()
	assert.Nil(t, acks)
}

func TestGetAcks_MultipleBatches(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	for i := 0; i < 35; i++ {
		rb.Insert(1, uint64(i*10), []byte("data"))
	}

	// First batch
	acks := rb.GetAcks()
	assert.Equal(t, 15, len(acks))

	// Second batch
	acks = rb.GetAcks()
	assert.Equal(t, 15, len(acks))

	// Third batch
	acks = rb.GetAcks()
	assert.Equal(t, 5, len(acks))

	// Should be empty now
	acks = rb.GetAcks()
	assert.Nil(t, acks)
}

func TestGetAcks_ExactBatchSize(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	for i := 0; i < 15; i++ {
		rb.Insert(1, uint64(i*10), []byte("data"))
	}

	acks := rb.GetAcks()
	assert.Equal(t, 15, len(acks))

	acks = rb.GetAcks()
	assert.Nil(t, acks)
}
