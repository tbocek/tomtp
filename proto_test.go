package tomtp

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncodeDecodePayload(t *testing.T) {
	// Test case 1: Encode and decode a payload with all fields set
	streamId := uint32(1)
	lastGoodSn := uint32(10)
	sackRanges := []SackRange{{from: 1, to: 10}, {from: 20, to: 30}}
	rcvWndSize := uint32(100)
	close := true
	finAck := true
	data := []byte("test data")

	buf := new(bytes.Buffer)
	_, err := EncodePayload(streamId, &lastGoodSn, sackRanges, rcvWndSize, close, finAck, 12, data, buf)
	if err != nil {
		t.Fatalf("Error encoding payload: %v", err)
	}

	payload, err := DecodePayload(buf, buf.Len())
	if err != nil {
		t.Fatalf("Error decoding payload: %v", err)
	}

	assert.Equal(t, streamId, payload.StreamId)
	assert.Equal(t, lastGoodSn, *payload.LastGoodSn)
	assert.Equal(t, len(sackRanges), len(payload.SackRanges))
	for i, sackRange := range payload.SackRanges {
		assert.Equal(t, sackRanges[i].from, sackRange.from)
		assert.Equal(t, sackRanges[i].to, sackRange.to)
	}
	assert.Equal(t, rcvWndSize, payload.RcwWndSize)
	assert.Equal(t, uint32(12), payload.Sn)
	assert.Equal(t, close, payload.Close)
	assert.Equal(t, finAck, payload.FinAck)
	assert.Equal(t, data, payload.Data)

	// Test case 2: Encode and decode a payload with only required fields
	streamId = uint32(2)
	lastGoodSn = uint32(0)
	sackRanges = nil
	rcvWndSize = uint32(0)
	close = false
	finAck = false
	data = []byte("")

	buf = new(bytes.Buffer)
	_, err = EncodePayload(streamId, &lastGoodSn, sackRanges, rcvWndSize, close, finAck, 13, data, buf)
	if err != nil {
		t.Fatalf("Error encoding payload: %v", err)
	}

	payload, err = DecodePayload(buf, buf.Len())
	if err != nil {
		t.Fatalf("Error decoding payload: %v", err)
	}

	assert.Equal(t, streamId, payload.StreamId)
	assert.Equal(t, lastGoodSn, *payload.LastGoodSn)
	assert.Equal(t, len(sackRanges), len(payload.SackRanges))
	assert.Equal(t, rcvWndSize, payload.RcwWndSize)
	assert.Equal(t, close, payload.Close)
	assert.Equal(t, finAck, payload.FinAck)
	assert.Nil(t, payload.Data)
}

// mockWriter is a mock implementation of io.Writer
type mockWriter struct {
	data []byte
}

func (w *mockWriter) Write(p []byte) (n int, err error) {
	w.data = append(w.data, p...)
	return len(p), nil
}
