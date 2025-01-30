package tomtp

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math"
	"reflect"
	"testing"
)

func TestEncodeDecodeMinimalPayload(t *testing.T) {
	original := &Payload{
		StreamId:     12345,
		StreamOffset: 0,
		Data:         []byte{},
	}

	encoded, offset, err := EncodePayload(original)
	require.NoError(t, err, "Failed to encode minimal payload")
	require.Greater(t, offset, 0)

	decoded, offset, err := DecodePayload(encoded)
	require.NoError(t, err, "Failed to decode minimal payload")
	require.Greater(t, offset, 0)

	assert.Equal(t, original.StreamId, decoded.StreamId, "StreamId mismatch")
	assert.Equal(t, original.StreamOffset, decoded.StreamOffset, "StreamOffset mismatch")
	assert.Empty(t, decoded.Data, "Data should be empty")
}

func TestPayloadWithAllFeatures(t *testing.T) {
	original := &Payload{
		CloseOp:      CloseStream,
		IsSender:     true,
		StreamId:     1,
		StreamOffset: 9999,
		Data:         []byte("test data"),
		RcvWndSize:   1000,
		Acks: []Ack{
			{StreamId: 1, StreamOffset: 123456, Len: 10},
			{StreamId: 2, StreamOffset: 789012, Len: 20},
		},
	}

	encoded, offset, err := EncodePayload(original)
	require.NoError(t, err, "Failed to encode payload")
	require.Greater(t, offset, 0)

	decoded, offset, err := DecodePayload(encoded)
	require.NoError(t, err, "Failed to decode payload")
	require.Greater(t, offset, 0)

	assert.Equal(t, original.CloseOp, decoded.CloseOp)
	assert.Equal(t, original.IsSender, decoded.IsSender)
	assert.Equal(t, original.StreamId, decoded.StreamId)
	assert.Equal(t, original.StreamOffset, decoded.StreamOffset)
	assert.Equal(t, original.Data, decoded.Data)

	require.NotNil(t, decoded.Acks)
	assert.Equal(t, original.RcvWndSize, decoded.RcvWndSize)
	require.Equal(t, len(original.Acks), len(decoded.Acks))

	for i := range original.Acks {
		assert.Equal(t, original.Acks[i], decoded.Acks[i])
	}
}

func TestCloseOpBehavior(t *testing.T) {
	testCases := []struct {
		name    string
		closeOp CloseOp
	}{
		{"No Close", NoClose},
		{"Stream Close", CloseStream},
		{"Connection Close", CloseConnection},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			original := &Payload{
				CloseOp:      tc.closeOp,
				StreamId:     1,
				StreamOffset: 100,
				Data:         []byte("test"),
			}

			encoded, offset, err := EncodePayload(original)
			require.NoError(t, err)
			require.Greater(t, offset, 0)

			decoded, offset, err := DecodePayload(encoded)
			require.NoError(t, err)
			require.Greater(t, offset, 0)

			assert.Equal(t, tc.closeOp, decoded.CloseOp)
		})
	}
}

func TestLargeOffsets(t *testing.T) {
	testCases := []struct {
		name         string
		streamOffset uint64
		ackOffsets   []uint64
		rcvWndSize   uint64
	}{
		{
			name:         "All 32-bit values",
			streamOffset: uint32Max - 1,
			ackOffsets:   []uint64{uint32Max - 1, uint32Max - 2},
			rcvWndSize:   uint32Max - 1,
		},
		{
			name:         "All 64-bit values",
			streamOffset: uint64(uint32Max) + 1,
			ackOffsets:   []uint64{uint64(uint32Max) + 1, uint64(uint32Max) + 2},
			rcvWndSize:   uint64(uint32Max) + 1,
		},
		{
			name:         "Mixed values",
			streamOffset: uint64(uint32Max) + 1,
			ackOffsets:   []uint64{uint32Max - 1, uint64(uint32Max) + 1},
			rcvWndSize:   uint32Max - 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			acks := make([]Ack, len(tc.ackOffsets))
			for i, offset := range tc.ackOffsets {
				acks[i] = Ack{
					StreamId:     uint32(i + 1),
					StreamOffset: offset,
					Len:          uint16(i + 100),
				}
			}

			original := &Payload{
				StreamId:     1,
				StreamOffset: tc.streamOffset,
				Data:         []byte("test"),
				Acks:         acks,
				RcvWndSize:   tc.rcvWndSize,
			}

			encoded, offset, err := EncodePayload(original)
			require.NoError(t, err)
			require.Greater(t, offset, 0)

			decoded, offset, err := DecodePayload(encoded)
			require.NoError(t, err)
			require.Greater(t, offset, 0)

			assert.Equal(t, original.StreamOffset, decoded.StreamOffset)
			assert.Equal(t, original.RcvWndSize, decoded.RcvWndSize)
			for i, ack := range original.Acks {
				assert.Equal(t, ack.StreamOffset, decoded.Acks[i].StreamOffset)
			}
		})
	}
}

func TestEmptyData(t *testing.T) {
	t.Run("Empty Data With Required Fields", func(t *testing.T) {
		original := &Payload{
			StreamId:     1,
			StreamOffset: 100,
			Data:         []byte{},
		}
		encoded, offset, err := EncodePayload(original)
		require.NoError(t, err)
		require.Greater(t, offset, 0)

		decoded, offset, err := DecodePayload(encoded)
		require.NoError(t, err)
		require.Greater(t, offset, 0)

		assert.Equal(t, original.StreamId, decoded.StreamId, "StreamId should be present")
		assert.Equal(t, original.StreamOffset, decoded.StreamOffset, "StreamOffset should be present")
		assert.Empty(t, decoded.Data, "Data should be empty")
	})
}

func TestAckHandling(t *testing.T) {
	t.Run("Maximum ACK Count", func(t *testing.T) {
		acks := make([]Ack, 7) // Maximum allowed
		for i := range acks {
			acks[i] = Ack{StreamId: uint32(i), StreamOffset: uint64(i * 1000), Len: uint16(i)}
		}

		original := &Payload{
			StreamId:     1,
			StreamOffset: 100,
			Data:         []byte("test"),
			Acks:         acks,
			RcvWndSize:   1000,
		}

		encoded, offset, err := EncodePayload(original)
		require.NoError(t, err)
		require.Greater(t, offset, 0)

		decoded, offset, err := DecodePayload(encoded)
		require.NoError(t, err)
		require.Greater(t, offset, 0)

		assert.Equal(t, len(original.Acks), len(decoded.Acks))
		for i := range original.Acks {
			assert.Equal(t, original.Acks[i], decoded.Acks[i])
		}
	})

	t.Run("Too Many ACKs", func(t *testing.T) {
		acks := make([]Ack, 16) // One more than maximum
		original := &Payload{
			StreamId:     1,
			StreamOffset: 100,
			Data:         []byte("test"),
			Acks:         acks,
			RcvWndSize:   1000,
		}

		_, _, err := EncodePayload(original)
		assert.Error(t, err, "too many Acks")
	})
}

func TestGetCloseOp(t *testing.T) {
	testCases := []struct {
		name        string
		streamClose bool
		connClose   bool
		expected    CloseOp
	}{
		{"No Close", false, false, NoClose},
		{"Stream Close", true, false, CloseStream},
		{"Connection Close", false, true, CloseConnection},
		{"Both Set (Connection Close takes precedence)", true, true, CloseConnection},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := GetCloseOp(tc.streamClose, tc.connClose)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func FuzzPayload(f *testing.F) {
	// Add seed corpus with valid and edge case payloads
	payloads := []*Payload{
		{
			StreamId:     1,
			StreamOffset: 100,
			Data:         []byte("test data"),
			RcvWndSize:   1000,
			Acks:         []Ack{{StreamId: 1, StreamOffset: 200, Len: 10}},
		},
		{
			StreamId:     math.MaxUint32,
			StreamOffset: math.MaxUint64,
			Data:         []byte{},
		},
	}

	for _, p := range payloads {
		encoded, _, err := EncodePayload(p)
		if err != nil {
			continue
		}
		f.Add(encoded)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, _, err := DecodePayload(data)
		if err != nil {
			t.Skip()
		}

		// Re-encode and decode to verify
		reEncoded, _, err := EncodePayload(decoded)
		if err != nil {
			t.Skip()
		}

		reDecoded, _, err := DecodePayload(reEncoded)
		if err != nil {
			t.Skip()
		}

		// Compare original decoded with re-decoded
		if !reflect.DeepEqual(decoded, reDecoded) {
			t.Fatal("re-encoded/decoded payload differs from original")
		}
	})
}
