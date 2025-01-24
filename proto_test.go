package tomtp

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestEncodeDecodeMinimalPayload(t *testing.T) {
	original := &Payload{
		Data: &Data{
			StreamId: 12345,
			Data:     []byte("123"),
		},
	}

	encoded, err := EncodePayload(original)
	if err != nil {
		t.Fatalf("Failed to encode minimal payload: %v", err)
	}

	decoded, err := DecodePayload(encoded)
	if err != nil {
		t.Fatalf("Failed to decode minimal payload: %v", err)
	}

	if decoded.Data.StreamId != original.Data.StreamId {
		t.Errorf("StreamId mismatch: got %d, want %d", decoded.Data.StreamId, original.Data.StreamId)
	}
}

func TestPayloadWithAllFlags(t *testing.T) {
	original := &Payload{
		StreamFlagClose:     true,
		CloseConnectionFlag: true,
		IsRecipient:         true,
		RcvWndSize:          1000,
		Acks: []Ack{
			{StreamId: 1, StreamOffset: 123456, Len: 10},
			{StreamId: 2, StreamOffset: 789012, Len: 20},
		},
		Data: &Data{
			StreamId:     1,
			StreamOffset: 9999,
			Data:         []byte("test data"),
		},
		Filler: []byte("filler"),
	}

	encoded, err := EncodePayload(original)
	if err != nil {
		t.Fatalf("Failed to encode payload: %v", err)
	}

	decoded, err := DecodePayload(encoded)
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	// Compare all fields
	assert.Equal(t, original.StreamFlagClose, decoded.StreamFlagClose)
	assert.Equal(t, original.CloseConnectionFlag, decoded.CloseConnectionFlag)
	assert.Equal(t, original.IsRecipient, decoded.IsRecipient)
	assert.Equal(t, original.RcvWndSize, decoded.RcvWndSize)
	assert.Equal(t, original.Data.StreamId, decoded.Data.StreamId)
	assert.Equal(t, original.Data.StreamOffset, decoded.Data.StreamOffset)
	assert.Equal(t, original.Data.Data, decoded.Data.Data)
	assert.Equal(t, original.Filler, decoded.Filler)

	// Compare Acks
	if len(original.Acks) != len(decoded.Acks) {
		t.Errorf("Ack count mismatch: got %d, want %d", len(decoded.Acks), len(original.Acks))
	}
	for i := range original.Acks {
		assert.Equal(t, original.Acks[i].StreamId, decoded.Acks[i].StreamId)
		assert.Equal(t, original.Acks[i].StreamOffset, decoded.Acks[i].StreamOffset)
		assert.Equal(t, original.Acks[i].Len, decoded.Acks[i].Len)
	}
}

func TestInvalidAckCount(t *testing.T) {
	payload := &Payload{
		RcvWndSize: 1000,
		Acks:       make([]Ack, 16),
	}

	_, err := EncodePayload(payload)
	if err != ErrInvalidAckCount {
		t.Errorf("Expected ErrInvalidAckCount, got %v", err)
	}
}

func TestPayloadTooSmall(t *testing.T) {
	_, err := DecodePayload(make([]byte, PayloadMinSize-1))
	if err != ErrPayloadTooSmall {
		t.Errorf("Expected ErrPayloadTooSmall, got %v", err)
	}
}

func TestMaximumAckCount(t *testing.T) {
	original := &Payload{
		RcvWndSize: 1000,
		Acks:       make([]Ack, 15),
	}

	// Fill Acks with test values
	for i := range original.Acks {
		original.Acks[i] = Ack{
			StreamId:     uint32(i),
			StreamOffset: uint64(i) << 40,
			Len:          uint16(i),
		}
	}

	encoded, err := EncodePayload(original)
	if err != nil {
		t.Fatalf("Failed to encode payload with max Acks: %v", err)
	}

	decoded, err := DecodePayload(encoded)
	if err != nil {
		t.Fatalf("Failed to decode payload with max Acks: %v", err)
	}

	if !reflect.DeepEqual(original.Acks, decoded.Acks) {
		t.Errorf("Acks mismatch")
	}
}

func TestLargeData(t *testing.T) {
	data := make([]byte, 1024*1024) // 1MB of data
	for i := range data {
		data[i] = byte(i % 256)
	}

	original := &Payload{
		Data: &Data{
			StreamId:     1,
			StreamOffset: 12345,
			Data:         data,
		},
	}

	encoded, err := EncodePayload(original)
	if err != nil {
		t.Fatalf("Failed to encode payload with large data: %v", err)
	}

	decoded, err := DecodePayload(encoded)
	if err != nil {
		t.Fatalf("Failed to decode payload with large data: %v", err)
	}

	if !bytes.Equal(original.Data.Data, decoded.Data.Data) {
		t.Error("Large data mismatch")
	}
}

func TestAck48BitMask(t *testing.T) {
	original := &Payload{
		RcvWndSize: 1000,
		Acks: []Ack{
			{
				StreamId:     1,
				StreamOffset: 0xFFFFFFFFFFFFFF, // All 48 bits set
				Len:          100,
			},
		},
	}

	encoded, err := EncodePayload(original)
	if err != nil {
		t.Fatalf("Failed to encode payload: %v", err)
	}

	decoded, err := DecodePayload(encoded)
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	// Check if only 48 bits are preserved
	expected := uint64(0x0000FFFFFFFFFFFF)
	if decoded.Acks[0].StreamOffset != expected {
		t.Errorf("StreamOffset not properly masked to 48 bits: got %x, want %x",
			decoded.Acks[0].StreamOffset, expected)
	}
}

func TestEmptyPayloadWithFlags(t *testing.T) {
	testCases := []struct {
		name    string
		payload *Payload
	}{
		{
			name: "Close flag only",
			payload: &Payload{
				StreamFlagClose:     true,
				CloseConnectionFlag: true,
				Data: &Data{
					StreamId: 1,
					Data:     []byte("123"),
				},
			},
		},
		{
			name: "Role flag only",
			payload: &Payload{
				IsRecipient: true,
				Filler:      []byte("123"),
			},
		},
		{
			name: "Data with offset",
			payload: &Payload{
				Data: &Data{
					StreamId:     1,
					StreamOffset: 12345,
					Data:         []byte("123"),
				},
			},
		},
		{
			name: "Filler flag with min filler",
			payload: &Payload{
				Data: &Data{
					StreamId: 1,
				},
				Filler: []byte("123"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := EncodePayload(tc.payload)
			assert.NoError(t, err)

			decoded, err := DecodePayload(encoded)
			assert.NoError(t, err)

			assert.Equal(t, tc.payload.StreamFlagClose, decoded.StreamFlagClose)
			assert.Equal(t, tc.payload.CloseConnectionFlag, decoded.CloseConnectionFlag)
			assert.Equal(t, tc.payload.IsRecipient, decoded.IsRecipient)
			if tc.payload.Data != nil {
				assert.Equal(t, tc.payload.Data.StreamId, decoded.Data.StreamId)
				assert.Equal(t, tc.payload.Data.StreamOffset, decoded.Data.StreamOffset)
				assert.Equal(t, tc.payload.Data.Data, decoded.Data.Data)
			}
			assert.Equal(t, tc.payload.Filler, decoded.Filler)
		})
	}
}

func TestFillerLengthLimit(t *testing.T) {
	payload := &Payload{
		Data: &Data{
			StreamId: 1,
		},
		Filler: make([]byte, 65536),
	}

	_, err := EncodePayload(payload)
	if err != ErrFillerTooLarge {
		t.Errorf("Expected ErrFillerTooLarge for filler size 65536, got %v", err)
	}

	// Test max allowed size
	payload.Filler = make([]byte, 65535)
	_, err = EncodePayload(payload)
	if err != nil {
		t.Errorf("Expected no error for max filler size 65535, got %v", err)
	}
}

func TestDataWithStreamOffset(t *testing.T) {
	testCases := []struct {
		name         string
		streamId     uint32
		streamOffset uint64
		data         []byte
	}{
		{
			name:         "Max 48-bit StreamOffset",
			streamId:     1,
			streamOffset: 0x0000FFFFFFFFFFFF,
			data:         []byte("test"),
		},
		{
			name:         "StreamOffset with upper bits set",
			streamId:     1,
			streamOffset: 0xFFFFFFFFFFFFFFFF,
			data:         []byte("test"),
		},
		{
			name:         "Min data",
			streamId:     1,
			streamOffset: 123,
			data:         []byte("123"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			original := &Payload{
				Data: &Data{
					StreamId:     tc.streamId,
					StreamOffset: tc.streamOffset,
					Data:         tc.data,
				},
			}

			encoded, err := EncodePayload(original)
			assert.NoError(t, err)

			decoded, err := DecodePayload(encoded)
			assert.NoError(t, err)

			// Check StreamOffset is properly masked to 48 bits
			expectedOffset := tc.streamOffset & 0x0000FFFFFFFFFFFF
			assert.Equal(t, expectedOffset, decoded.Data.StreamOffset)
			assert.Equal(t, tc.data, decoded.Data.Data)
		})
	}
}

func TestCombinedFlags(t *testing.T) {
	testCases := []struct {
		name    string
		payload *Payload
	}{
		{
			name: "Data and ACK",
			payload: &Payload{
				Data: &Data{
					StreamId:     1,
					StreamOffset: 123,
					Data:         []byte("test"),
				},
				RcvWndSize: 1000,
				Acks: []Ack{
					{
						StreamId:     1,
						StreamOffset: 456,
						Len:          100,
					},
				},
			},
		},
		{
			name: "Data and Filler",
			payload: &Payload{
				Data: &Data{
					StreamId:     1,
					StreamOffset: 123,
					Data:         []byte("test"),
				},
				Filler: []byte("fill"),
			},
		},
		{
			name: "ACK and Filler",
			payload: &Payload{
				RcvWndSize: 1000,
				Acks: []Ack{
					{
						StreamId:     1,
						StreamOffset: 123,
						Len:          50,
					},
					{
						StreamId:     2,
						StreamOffset: 456,
						Len:          100,
					},
				},
				Filler: []byte("fill"),
			},
		},
		{
			name: "All optional fields",
			payload: &Payload{
				Data: &Data{
					StreamId:     1,
					StreamOffset: 123,
					Data:         []byte("test"),
				},
				RcvWndSize: 1000,
				Acks: []Ack{
					{
						StreamId:     1,
						StreamOffset: 456,
						Len:          100,
					},
				},
				Filler: []byte("fill"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := EncodePayload(tc.payload)
			assert.NoError(t, err)

			decoded, err := DecodePayload(encoded)
			assert.NoError(t, err)

			if tc.payload.Data != nil {
				assert.Equal(t, tc.payload.Data.Data, decoded.Data.Data)
				assert.Equal(t, tc.payload.Data.StreamOffset, decoded.Data.StreamOffset)
				assert.Equal(t, tc.payload.Data.StreamId, decoded.Data.StreamId)
			}
			assert.Equal(t, tc.payload.Filler, decoded.Filler)
			assert.Equal(t, tc.payload.Acks, decoded.Acks)
		})
	}
}
