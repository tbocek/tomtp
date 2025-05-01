package tomtp

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestReceiveBuffer_SingleSegment(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 0, []byte("data"), false)
	assert.Equal(t, RcvInsertOk, status)

	offset, data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("data"), data.data)

	// Verify empty after reading
	_, data = rb.RemoveOldestInOrder(1)
	require.Empty(t, data)
}

func TestReceiveBuffer_DuplicateSegment(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 0, []byte("data"), false)
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 0, []byte("data"), false)
	assert.Equal(t, RcvInsertDuplicate, status)

	offset, data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("data"), data.data)
}

func TestReceiveBuffer_GapBetweenSegments(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 10, []byte("later"), false)
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 0, []byte("early"), false)
	assert.Equal(t, RcvInsertOk, status)

	// Should get early segment first
	offset, data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("early"), data.data)

	// Then later segment
	offset, data = rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Nil(t, data)
}

func TestReceiveBuffer_MultipleStreams(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert segments from different streams
	status := rb.Insert(1, 0, []byte("stream1-first"), false)
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(2, 0, []byte("stream2-first"), false)
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 13, []byte("stream1-second"), false)
	assert.Equal(t, RcvInsertOk, status)

	// Read from stream 1
	offset, data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("stream1-first"), data.data)

	// Read from stream 2
	offset, data = rb.RemoveOldestInOrder(2)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("stream2-first"), data.data)

	// Read second segment from stream 1
	offset, data = rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(13), offset)
	assert.Equal(t, []byte("stream1-second"), data.data)
}

func TestReceiveBuffer_BufferFullExact(t *testing.T) {
	rb := NewReceiveBuffer(4)

	status := rb.Insert(1, 0, []byte("data"), false)
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 4, []byte("more"), false)
	assert.Equal(t, RcvInsertBufferFull, status)

	offset, data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("data"), data.data)
}

func TestReceiveBuffer_RemoveWithHigherOffset(t *testing.T) {
	rb := NewReceiveBuffer(4)

	status := rb.Insert(1, 0, []byte("12345"), false)
	assert.Equal(t, RcvInsertBufferFull, status)

	offset, data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Nil(t, data)
}

func TestReceiveBuffer_RemoveWithHigherOffset_EmptyAfterLast(t *testing.T) {
	rb := NewReceiveBuffer(4)

	status := rb.Insert(1, 0, []byte("1"), false)
	assert.Equal(t, RcvInsertOk, status)

	offset, data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("1"), data.data)

	// Should be empty after reading
	_, data = rb.RemoveOldestInOrder(1)
	require.Empty(t, data)
}
