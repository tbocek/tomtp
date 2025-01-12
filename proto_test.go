package tomtp

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestEncodeDecodeMinimalPayload(t *testing.T) {
	original := &Payload{
		StreamId: 12345,
		Data:     []byte("123"),
	}

	encoded, err := EncodePayload(original)
	if err != nil {
		t.Fatalf("Failed to encode minimal payload: %v", err)
	}

	decoded, err := DecodePayload(encoded)
	if err != nil {
		t.Fatalf("Failed to decode minimal payload: %v", err)
	}

	if decoded.StreamId != original.StreamId {
		t.Errorf("StreamId mismatch: got %d, want %d", decoded.StreamId, original.StreamId)
	}
}

func TestPayloadWithAllFlags(t *testing.T) {
	original := &Payload{
		StreamId:            1,
		StreamFlagClose:     true,
		CloseConnectionFlag: true,
		AckCount:            2,
		IsRecipient:         true,
		RcvWndSize:          1000,
		AckSns:              []uint64{123456, 789012},
		StreamSn:            9999,
		Data:                []byte("test data"),
		Filler:              []byte("filler"),
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
	if !reflect.DeepEqual(original, decoded) {
		t.Errorf("Decoded payload doesn't match original")
		t.Errorf("Original: %+v", original)
		t.Errorf("Decoded: %+v", decoded)
	}
}

func TestInvalidAckCount(t *testing.T) {
	payload := &Payload{
		StreamId:   1,
		AckCount:   16, // Invalid - should be 0-15
		RcvWndSize: 1000,
		AckSns:     make([]uint64, 16),
	}

	_, err := EncodePayload(payload)
	if err != ErrInvalidAckCount {
		t.Errorf("Expected ErrInvalidAckCount, got %v", err)
	}
}

func TestPayloadTooSmall(t *testing.T) {
	_, err := DecodePayload(make([]byte, MinPayloadSize-PayloadMinSize-1))
	if err != ErrPayloadTooSmall {
		t.Errorf("Expected ErrPayloadTooSmall, got %v", err)
	}
}

func TestMaximumAckCount(t *testing.T) {
	original := &Payload{
		StreamId:   1,
		AckCount:   15,
		RcvWndSize: 1000,
		AckSns:     make([]uint64, 15),
	}

	// Fill AckSns with test values
	for i := range original.AckSns {
		original.AckSns[i] = uint64(i) + 1
	}

	encoded, err := EncodePayload(original)
	if err != nil {
		t.Fatalf("Failed to encode payload with max ACKs: %v", err)
	}

	decoded, err := DecodePayload(encoded)
	if err != nil {
		t.Fatalf("Failed to decode payload with max ACKs: %v", err)
	}

	if !reflect.DeepEqual(original.AckSns, decoded.AckSns) {
		t.Errorf("AckSns mismatch")
	}
}

func TestLargeData(t *testing.T) {
	data := make([]byte, 1024*1024) // 1MB of data
	for i := range data {
		data[i] = byte(i % 256)
	}

	original := &Payload{
		StreamId: 1,
		StreamSn: 12345,
		Data:     data,
	}

	encoded, err := EncodePayload(original)
	if err != nil {
		t.Fatalf("Failed to encode payload with large data: %v", err)
	}

	decoded, err := DecodePayload(encoded)
	if err != nil {
		t.Fatalf("Failed to decode payload with large data: %v", err)
	}

	if !bytes.Equal(original.Data, decoded.Data) {
		t.Error("Large data mismatch")
	}
}

func TestAckSn48BitMask(t *testing.T) {
	original := &Payload{
		StreamId:   1,
		AckCount:   1,
		RcvWndSize: 1000,
		AckSns:     []uint64{0xFFFFFFFFFFFFFF}, // All bits set
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
	if decoded.AckSns[0] != expected {
		t.Errorf("AckSn not properly masked to 48 bits: got %x, want %x",
			decoded.AckSns[0], expected)
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
				StreamId:            1,
				StreamFlagClose:     true,
				CloseConnectionFlag: true,
				Data:                []byte("123"),
			},
		},
		{
			name: "Role flag only",
			payload: &Payload{
				StreamId:    1,
				IsRecipient: true,
				Filler:      []byte("123"),
			},
		},
		{
			name: "Data flag with min data",
			payload: &Payload{
				StreamId: 1,
				StreamSn: 12345,
				Data:     []byte("123"),
			},
		},
		{
			name: "Filler flag with min filler",
			payload: &Payload{
				StreamId: 1,
				Filler:   []byte("123"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := EncodePayload(tc.payload)
			if err != nil {
				t.Fatalf("Failed to encode payload: %v", err)
			}

			decoded, err := DecodePayload(encoded)
			if err != nil {
				t.Fatalf("Failed to decode payload: %v", err)
			}

			if !reflect.DeepEqual(tc.payload, decoded) {
				t.Errorf("Payload mismatch\nOriginal: %+v\nDecoded: %+v",
					tc.payload, decoded)
			}
		})
	}
}

func TestFillerLengthLimit(t *testing.T) {
	payload := &Payload{
		StreamId: 1,
		Filler:   make([]byte, 65536),
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

func TestDataAndStreamSn(t *testing.T) {
	testCases := []struct {
		name     string
		streamSn uint64
		data     []byte
	}{
		{
			name:     "Max 48-bit StreamSn",
			streamSn: 0x0000FFFFFFFFFFFF,
			data:     []byte("test"),
		},
		{
			name:     "StreamSn with upper bits set",
			streamSn: 0xFFFFFFFFFFFFFFFF,
			data:     []byte("test"),
		},
		{
			name:     "Min data",
			streamSn: 123,
			data:     []byte("123"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			original := &Payload{
				StreamId: 1,
				StreamSn: tc.streamSn,
				Data:     tc.data,
			}

			encoded, err := EncodePayload(original)
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}

			decoded, err := DecodePayload(encoded)
			if err != nil {
				t.Fatalf("Failed to decode: %v", err)
			}

			// Check StreamSn is properly masked to 48 bits
			expectedSn := tc.streamSn & 0x0000FFFFFFFFFFFF
			if decoded.StreamSn != expectedSn {
				t.Errorf("StreamSn mismatch: got %x, want %x", decoded.StreamSn, expectedSn)
			}

			if !bytes.Equal(decoded.Data, tc.data) {
				t.Errorf("Data mismatch: got %x, want %x", decoded.Data, tc.data)
			}
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
				StreamId:   1,
				AckCount:   1,
				StreamSn:   123,
				Data:       []byte("test"),
				RcvWndSize: 1000,
				AckSns:     []uint64{456},
			},
		},
		{
			name: "Data and Filler",
			payload: &Payload{
				StreamId: 1,
				StreamSn: 123,
				Data:     []byte("test"),
				Filler:   []byte("fill"),
			},
		},
		{
			name: "ACK and Filler",
			payload: &Payload{
				StreamId:   1,
				AckCount:   2,
				RcvWndSize: 1000,
				AckSns:     []uint64{123, 456},
				Filler:     []byte("fill"),
			},
		},
		{
			name: "All optional fields",
			payload: &Payload{
				StreamId:   1,
				AckCount:   1,
				StreamSn:   123,
				Data:       []byte("test"),
				RcvWndSize: 1000,
				AckSns:     []uint64{456},
				Filler:     []byte("fill"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := EncodePayload(tc.payload)
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}

			decoded, err := DecodePayload(encoded)
			if err != nil {
				t.Fatalf("Failed to decode: %v", err)
			}

			if !bytes.Equal(decoded.Data, tc.payload.Data) {
				t.Errorf("Data mismatch")
			}
			if !bytes.Equal(decoded.Filler, tc.payload.Filler) {
				t.Errorf("Filler mismatch")
			}
			if decoded.StreamSn != tc.payload.StreamSn {
				t.Errorf("StreamSn mismatch")
			}
			if !reflect.DeepEqual(decoded.AckSns, tc.payload.AckSns) {
				t.Errorf("AckSns mismatch")
			}
		})
	}
}

func TestZeroValues(t *testing.T) {
	testCases := []struct {
		name    string
		payload *Payload
	}{
		{
			name: "Zero StreamId",
			payload: &Payload{
				StreamId: 0,
				Data:     []byte("test"),
			},
		},
		{
			name: "Zero StreamSn",
			payload: &Payload{
				StreamId: 1,
				StreamSn: 0,
				Data:     []byte("test"),
			},
		},
		{
			name: "Zero RcvWndSize",
			payload: &Payload{
				StreamId:   1,
				AckCount:   1,
				RcvWndSize: 0,
				AckSns:     []uint64{123},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := EncodePayload(tc.payload)
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}

			decoded, err := DecodePayload(encoded)
			if err != nil {
				t.Fatalf("Failed to decode: %v", err)
			}

			if !reflect.DeepEqual(tc.payload, decoded) {
				t.Errorf("Payload mismatch\nOriginal: %+v\nDecoded: %+v",
					tc.payload, decoded)
			}
		})
	}
}

func TestBoundaryConditions(t *testing.T) {
	// Test with exactly MinPayloadSize bytes
	minPayload := &Payload{
		StreamId: 1,
		Data:     []byte("123"),
	}
	encoded, err := EncodePayload(minPayload)
	if err != nil {
		t.Fatalf("Failed to encode minimal payload: %v", err)
	}
	if len(encoded) != 14 {
		t.Errorf("Expected encoded size %d, got %d", PayloadMinSize, len(encoded))
	}

	// Test decoding with exactly MinPayloadSize bytes
	decoded, err := DecodePayload(encoded)
	if err != nil {
		t.Fatalf("Failed to decode minimal payload: %v", err)
	}
	if decoded.StreamId != minPayload.StreamId {
		t.Errorf("StreamId mismatch after decoding minimal payload")
	}
}

func FuzzProtoPayload(f *testing.F) {
	// Add seed corpus with various sizes
	seeds := [][]byte{
		[]byte("12"),       // 2 bytes - should fail
		[]byte("123"),      // 3 bytes - boundary case
		[]byte("1234"),     // 4 bytes - valid
		[]byte("initial"),  // normal case
		make([]byte, 0),    // 2 zero bytes - should fail
		make([]byte, 1),    // 3 zero bytes - boundary
		make([]byte, 1000), // large payload
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create initial payload with data
		original := &Payload{
			StreamId: 1,
			Data:     data,
		}

		// For data smaller than minimum size, verify error
		if len(data) == 0 {
			_, err := EncodePayload(original)
			assert.Error(t, err)
			assert.Equal(t, "payload size below minimum of 8 bytes", err.Error())
			return
		}

		// For valid data sizes, test full encode/decode cycle
		encoded, err := EncodePayload(original)
		assert.NoError(t, err)

		decoded, err := DecodePayload(encoded)
		assert.NoError(t, err)

		// Verify all fields match
		assert.Equal(t, original.StreamId, decoded.StreamId)
		assert.True(t, bytes.Equal(original.Data, decoded.Data))

		// Add filler and test again
		original.Filler = data // use same data for filler

		encoded, err = EncodePayload(original)
		assert.NoError(t, err)

		decoded, err = DecodePayload(encoded)
		assert.NoError(t, err)

		// Verify all fields including filler
		assert.Equal(t, original.StreamId, decoded.StreamId)
		assert.True(t, bytes.Equal(original.Data, decoded.Data))
		assert.True(t, bytes.Equal(original.Filler, decoded.Filler))

		// Test with ACKs
		original.AckCount = 1
		original.AckSns = []uint64{0xFFFFFFFFFFFFFF} // test 48-bit handling
		original.RcvWndSize = 1000

		encoded, err = EncodePayload(original)
		assert.NoError(t, err)

		decoded, err = DecodePayload(encoded)
		assert.NoError(t, err)

		// Verify ACK fields
		assert.Equal(t, original.AckCount, decoded.AckCount)
		assert.Equal(t, original.RcvWndSize, decoded.RcvWndSize)
		assert.Equal(t, uint64(0x0000FFFFFFFFFFFF), decoded.AckSns[0]) // verify 48-bit mask
	})
}
