package tomtp

import (
	"math"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeMinimalPayload(t *testing.T) {
	original := &PayloadMeta{
		StreamId:     12345,
		StreamOffset: 0,
	}

	encoded, _, err := EncodePayload(original, []byte{})
	require.NoError(t, err, "Failed to encode minimal payload")

	decoded, _, decodedData, err := DecodePayload(encoded)
	require.NoError(t, err, "Failed to decode minimal payload")

	assert.Equal(t, original.StreamId, decoded.StreamId, "StreamId mismatch")
	assert.Equal(t, original.StreamOffset, decoded.StreamOffset, "StreamOffset mismatch")
	assert.Empty(t, decodedData, "Data should be empty")
}

func TestPayloadWithAllFeatures(t *testing.T) {
	original := &PayloadMeta{
		CloseOp:      CloseStream,
		IsSender:     true,
		StreamId:     1,
		StreamOffset: 9999,
		RcvWndSize:   1000,
		Acks: []Ack{
			{StreamId: 1, StreamOffset: 123456, Len: 10},
			{StreamId: 2, StreamOffset: 789012, Len: 20},
		},
	}

	originalData := []byte("test data")

	encoded, _, err := EncodePayload(original, originalData)
	require.NoError(t, err, "Failed to encode payload")

	decoded, _, decodedData, err := DecodePayload(encoded)
	require.NoError(t, err, "Failed to decode payload")

	assert.Equal(t, original.CloseOp, decoded.CloseOp)
	assert.Equal(t, original.IsSender, decoded.IsSender)
	assert.Equal(t, original.StreamId, decoded.StreamId)
	assert.Equal(t, original.StreamOffset, decoded.StreamOffset)
	assert.Equal(t, originalData, decodedData)

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
			original := &PayloadMeta{
				CloseOp:      tc.closeOp,
				StreamId:     1,
				StreamOffset: 100,
			}

			originalData := []byte("test")

			encoded, _, err := EncodePayload(original, originalData)
			require.NoError(t, err)

			decoded, _, _, err := DecodePayload(encoded)
			require.NoError(t, err)

			assert.Equal(t, tc.closeOp, decoded.CloseOp)
		})
	}
}

func TestEmptyData(t *testing.T) {
	t.Run("Empty Data With Required Fields", func(t *testing.T) {
		original := &PayloadMeta{
			StreamId:     1,
			StreamOffset: 100,
		}
		encoded, _, err := EncodePayload(original, []byte{})
		require.NoError(t, err)

		decoded, _, decodedData, err := DecodePayload(encoded)
		require.NoError(t, err)

		assert.Equal(t, original.StreamId, decoded.StreamId, "StreamId should be present")
		assert.Equal(t, original.StreamOffset, decoded.StreamOffset, "StreamOffset should be present")
		assert.Empty(t, decodedData, "Data should be empty")
	})
}

func TestAckHandling(t *testing.T) {
	t.Run("Maximum ACK Count", func(t *testing.T) {
		acks := make([]Ack, 7) // Maximum allowed
		for i := range acks {
			acks[i] = Ack{StreamId: uint32(i), StreamOffset: uint64(i * 1000), Len: uint16(i)}
		}

		original := &PayloadMeta{
			StreamId:     1,
			StreamOffset: 100,
			Acks:         acks,
			RcvWndSize:   1000,
		}

		originalData := []byte("test")

		encoded, _, err := EncodePayload(original, originalData)
		require.NoError(t, err)

		decoded, _, _, err := DecodePayload(encoded)
		require.NoError(t, err)

		assert.Equal(t, len(original.Acks), len(decoded.Acks))
		for i := range original.Acks {
			assert.Equal(t, original.Acks[i], decoded.Acks[i])
		}
	})

	t.Run("Too Many ACKs", func(t *testing.T) {
		acks := make([]Ack, 16) // One more than maximum
		original := &PayloadMeta{
			StreamId:     1,
			StreamOffset: 100,
			Acks:         acks,
			RcvWndSize:   1000,
		}
		originalData := []byte("test")

		_, _, err := EncodePayload(original, originalData)
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
	payloads := []*PayloadMeta{
		{
			StreamId:     1,
			StreamOffset: 100,
			RcvWndSize:   1000,
			Acks:         []Ack{{StreamId: 1, StreamOffset: 200, Len: 10}},
		},
		{
			StreamId:     math.MaxUint32,
			StreamOffset: math.MaxUint64,
		},
	}

	for _, p := range payloads {
		originalData := []byte("test data")
		encoded, _, err := EncodePayload(p, originalData)
		if err != nil {
			continue
		}
		f.Add(encoded)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, _, payloadData, err := DecodePayload(data)
		if err != nil {
			t.Skip()
		}

		reEncoded, _, err := EncodePayload(decoded, payloadData)
		if err != nil {
			t.Skip()
		}

		reDecoded, _, reDecodedData, err := DecodePayload(reEncoded)
		if err != nil {
			t.Skip()
		}

		// Compare original decoded with re-decoded
		if !reflect.DeepEqual(decoded, reDecoded) || !reflect.DeepEqual(payloadData, reDecodedData) {
			t.Fatal("re-encoded/decoded payload differs from original")
		}
	})
}
