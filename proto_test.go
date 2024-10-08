package tomtp

import (
	"bytes"
	"fmt"
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
	if err != nil {
		t.Fatalf("Encoding failed: %v", err)
	}

	// Decode the payload
	decodedPayload, err := DecodePayload(&buf)
	if err != nil {
		t.Fatalf("Decoding failed: %v", err)
	}

	// Compare the original and decoded values
	if decodedPayload.StreamId != streamId {
		t.Errorf("StreamId mismatch: expected %v, got %v", streamId, decodedPayload.StreamId)
	}

	if decodedPayload.RcvWndSize != rcvWndSize {
		t.Errorf("RcvWndSize mismatch: expected %v, got %v", rcvWndSize, decodedPayload.RcvWndSize)
	}

	if decodedPayload.CloseFlag != closeFlag {
		t.Errorf("Close flag mismatch: expected %v, got %v", closeFlag, decodedPayload.CloseFlag)
	}

	if decodedPayload.AckSn != ackSn {
		t.Errorf("AckStartSn mismatch: expected %v, got %v", ackSn, decodedPayload.AckSn)
	}

	if !bytes.Equal(data, decodedPayload.Data) {
		t.Errorf("Data mismatch: expected %v, got %v", data, decodedPayload.Data)
	}
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
	payload := &Payload{
		StreamId:   rand.Uint32(),
		RcvWndSize: rand.Uint64() & 0x7FFFFFFFFFFFFFFF, // Ensure it's within 31-bit range
		AckSn:      rand.Uint64(),
		Data:       make([]byte, rand.Intn(100)),
	}

	// Randomly set the CloseFlag
	if rand.Float32() < 0.5 {
		payload.CloseFlag = true
	}

	// Generate random data
	rand.Read(payload.Data)

	return payload
}

func comparePayloads(t *testing.T, original, decoded *Payload) {
	if original.StreamId != decoded.StreamId {
		t.Errorf("StreamId mismatch: original %d, decoded %d", original.StreamId, decoded.StreamId)
	}

	if original.RcvWndSize != decoded.RcvWndSize {
		t.Errorf("RcvWndSize mismatch: original %d, decoded %d", original.RcvWndSize, decoded.RcvWndSize)
	}

	if original.AckSn != decoded.AckSn {
		t.Errorf("AckStartSn mismatch: original %d, decoded %d", original.AckSn, decoded.AckSn)
	}

	if original.CloseFlag != decoded.CloseFlag {
		t.Errorf("Close flag mismatch: original %v, decoded %v", original.CloseFlag, decoded.CloseFlag)
	}

	if !bytes.Equal(original.Data, decoded.Data) {
		t.Errorf("Data mismatch: original %v, decoded %v", original.Data, decoded.Data)
	}
}
