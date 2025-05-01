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
		IsClose:      true,
		IsSender:     true,
		StreamId:     1,
		StreamOffset: 9999,
		RcvWndSize:   1000,
		Ack:          &Ack{streamId: 1, offset: 123456, len: 10},
	}

	originalData := []byte("test data")

	encoded, _, err := EncodePayload(original, originalData)
	require.NoError(t, err, "Failed to encode payload")

	decoded, _, decodedData, err := DecodePayload(encoded)
	require.NoError(t, err, "Failed to decode payload")

	assert.Equal(t, original.IsClose, decoded.IsClose)
	assert.Equal(t, original.IsSender, decoded.IsSender)
	assert.Equal(t, original.StreamId, decoded.StreamId)
	assert.Equal(t, original.StreamOffset, decoded.StreamOffset)
	assert.Equal(t, originalData, decodedData)

	require.NotNil(t, decoded.Ack)
	assert.Equal(t, original.RcvWndSize, decoded.RcvWndSize)
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
		ack := &Ack{streamId: 0, offset: 0, len: 0}
		original := &PayloadMeta{
			StreamId:     1,
			StreamOffset: 100,
			Ack:          ack,
			RcvWndSize:   1000,
		}

		originalData := []byte("test")

		encoded, _, err := EncodePayload(original, originalData)
		require.NoError(t, err)

		decoded, _, _, err := DecodePayload(encoded)
		require.NoError(t, err)
		assert.Equal(t, original.Ack, decoded.Ack)
	})

}

func FuzzPayload(f *testing.F) {
	// Add seed corpus with valid and edge case payloads
	payloads := []*PayloadMeta{
		{
			StreamId:     1,
			StreamOffset: 100,
			RcvWndSize:   1000,
			Ack:          &Ack{streamId: 10, offset: 200, len: 10},
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
