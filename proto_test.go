package tomtp

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"log"
	"math/rand"
	"os"
	"testing"
	"time"
)

// Helper function to test encoding and decoding
func testEncodeDecode(t *testing.T, streamId uint32, rcvWndSize uint64, ackSn uint64, closeFlag bool, data []byte) {
	var buf bytes.Buffer

	// Encode the payload
	_, err := EncodePayload(streamId, closeFlag, rcvWndSize, ackSn, data, &buf)
	assert.NoError(t, err, "Encoding failed")

	// Decode the payload
	decodedPayload, err := DecodePayload(&buf)
	assert.NoError(t, err, "Decoding failed")

	// Compare the original and decoded values
	assert.Equal(t, streamId, decodedPayload.StreamId, "StreamId mismatch")

	// Verify flags are set correctly

	assert.Equal(t, closeFlag, decodedPayload.CloseFlag, "CloseFlag mismatch")

	assert.Equal(t, rcvWndSize&0x0000FFFFFFFFFFFF, decodedPayload.RcvWndSize, "RcvWndSize mismatch")

	assert.Equal(t, ackSn, decodedPayload.AckSn, "AckSn mismatch")

	assert.Equal(t, data, decodedPayload.Data, "Data mismatch")

}

func TestEncodeDecode_NoSackNoData(t *testing.T) {
	testEncodeDecode(t, 12345, 100000, 0, false, nil)
}

func TestEncodeDecode_AckOnly(t *testing.T) {
	testEncodeDecode(t, 12345, 100000, 5000, false, nil)
}

func TestEncodeDecode_CloseFlag(t *testing.T) {
	testEncodeDecode(t, 12345, 100000, 0, true, nil)
}

func TestEncodeDecode_DataOnly(t *testing.T) {
	data := []byte("Hello, World!")
	testEncodeDecode(t, 12345, 100000, 0, false, data)
}

func TestEncodeDecode_AckAndData(t *testing.T) {
	data := []byte("Hello, World!")
	testEncodeDecode(t, 12345, 100000, 5000, false, data)
}

func FuzzPayload(f *testing.F) {

	// Enable logging
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	rand.Seed(time.Now().UnixNano())

	f.Fuzz(func(t *testing.T, data []byte) {
		// Generate random payload
		payload := generateRandomPayload()

		fmt.Printf("Original payload: %+v\n", payload)
		fmt.Printf("Original data: %v\n", payload.Data)

		// Encode the payload
		var encodeBuf bytes.Buffer
		_, err := EncodePayload(
			payload.StreamId,
			payload.CloseFlag,
			payload.RcvWndSize,
			payload.AckSn,
			payload.Data,
			&encodeBuf,
		)
		if err != nil {
			return // Invalid input, skip this test case
		}

		// Decode the payload
		decodedPayload, err := DecodePayload(&encodeBuf)
		if err != nil {
			t.Fatalf("Failed to decode payload: %v", err)
		}

		// Compare original and decoded payloads
		comparePayloads(t, payload, decodedPayload)
	})
}

func generateRandomPayload() *Payload {

	flags := rand.Intn(2) > 0 // 0000 to 1111 in binary

	payload := &Payload{
		StreamId:   rand.Uint32(),
		CloseFlag:  flags,
		RcvWndSize: rand.Uint64() & 0x0000FFFFFFFFFFFF, // Ensure it's within 31-bit range
		AckSn:      rand.Uint64(),
		Data:       make([]byte, rand.Intn(100)),
	}

	// Generate random data
	rand.Read(payload.Data)

	return payload
}

func comparePayloads(t *testing.T, original, decoded *Payload) {
	assert.Equal(t, original.Version, decoded.Version, "Version mismatch")
	assert.Equal(t, original.StreamId, decoded.StreamId, "StreamId mismatch")
	assert.Equal(t, original.CloseFlag, decoded.CloseFlag, "Flags mismatch")
	assert.Equal(t, original.RcvWndSize&0x0000FFFFFFFFFFFF, decoded.RcvWndSize, "RcvWndSize mismatch")
	assert.Equal(t, original.AckSn, decoded.AckSn, "AckSn mismatch")
	if decoded.Data == nil {
		assert.Equal(t, original.Data, []byte{}, "Data mismatch")
	} else {
		assert.Equal(t, original.Data, decoded.Data, "Data mismatch")
	}
}
