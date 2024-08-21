package tomtp

import (
	"bytes"
	"testing"
)

// Helper function to test encoding and decoding
func testEncodeDecode(t *testing.T, value uint64, expectedBytes []byte) {
	buf := make([]byte, 8)
	bytesWritten, err := EncodeVaruint64(value, buf, 0)
	if err != nil {
		t.Fatalf("Encoding failed: %v", err)
	}

	if bytesWritten != len(expectedBytes) {
		t.Fatalf("Expected %d bytes written, but got %d", len(expectedBytes), bytesWritten)
	}

	for i := 0; i < len(expectedBytes); i++ {
		if buf[i] != expectedBytes[i] {
			t.Fatalf("Expected byte %d to be 0x%02x, but got 0x%02x", i, expectedBytes[i], buf[i])
		}
	}

	decodedValue, bytesRead, err := DecodeVaruint64(buf, 0)
	if err != nil {
		t.Fatalf("Decoding failed: %v", err)
	}

	if decodedValue != value {
		t.Fatalf("Expected decoded value to be %d, but got %d", value, decodedValue)
	}

	if bytesRead != len(expectedBytes) {
		t.Fatalf("Expected %d bytes read, but got %d", len(expectedBytes), bytesRead)
	}
}

func TestEncodeDecode1Byte(t *testing.T) {
	value := uint64(0x3F)
	expectedBytes := []byte{0x3F}
	testEncodeDecode(t, value, expectedBytes)
}

func TestEncodeDecode2Bytes(t *testing.T) {
	value := uint64(0x3FFF)
	expectedBytes := []byte{0x7F, 0xFF}
	testEncodeDecode(t, value, expectedBytes)
}

func TestEncodeDecode4Bytes(t *testing.T) {
	value := uint64(0x3FFFFFFF)
	expectedBytes := []byte{0xBF, 0xFF, 0xFF, 0xFF}
	testEncodeDecode(t, value, expectedBytes)
}

func TestEncodeDecode16432(t *testing.T) {
	value := uint64(16432)
	expectedBytes := []byte{0x80, 0x0, 0x40, 0x30}
	testEncodeDecode(t, value, expectedBytes)
}

func TestEncodeDecode8Bytes(t *testing.T) {
	buf := make([]byte, 8)
	_, err := EncodeVaruint64(0xFFFFFFFFFFFFFFFF, buf, 0)
	if err == nil {
		t.Fatalf("Expected higher than 62bit error, but got nil")
	}
}

func TestEncodeBufferTooSmall(t *testing.T) {
	buf := make([]byte, 1)
	_, err := EncodeVaruint64(0x3FFF, buf, 0)
	if err == nil {
		t.Fatalf("Expected buffer too small error, but got nil")
	}
}

func TestDecodeBufferTooSmall(t *testing.T) {
	buf := make([]byte, 1)
	decodedValue, _, err := DecodeVaruint64(buf, 0)
	if err != nil {
		t.Fatalf("Got error")
	}
	if decodedValue != 0 {
		t.Fatalf("Expected decoded value to be %d, but got %d", 0, decodedValue)
	}
}

// FuzzEncodeDecode tests encoding and decoding of random uint64 values in a loop.
func FuzzEncodeDecode(f *testing.F) {
	// Seed the fuzzer with some interesting values
	f.Add(uint64(0))
	f.Add(uint64(1))
	f.Add(uint64(0x3F))               // Max value for 1-byte encoding
	f.Add(uint64(0x3FFF))             // Max value for 2-byte encoding
	f.Add(uint64(0x3FFFFFFF))         // Max value for 4-byte encoding
	f.Add(uint64(0x3FFFFFFFFFFFFFFF)) // Max value for 8-byte encoding
	f.Add(uint64(0xFFFFFFFFFFFFFFFF)) // Maximum possible uint64 value (though not encodable by this function)

	// Define the fuzzer function
	f.Fuzz(func(t *testing.T, value uint64) {
		// Create a buffer large enough to hold the maximum encoded value
		buf := make([]byte, 8)

		// Encode the value
		bytesWritten, err := EncodeVaruint64(value, buf, 0)
		if err != nil {
			if value <= 0x3FFFFFFFFFFFFFFF {
				t.Fatalf("Encoding failed for valid value %d: %v", value, err)
			}
			return // Skip testing for unsupported sizes
		}

		// Decode the value
		decodedValue, bytesRead, err := DecodeVaruint64(buf, 0)
		if err != nil {
			t.Fatalf("Decoding failed: %v", err)
		}

		// Check that the decoded value matches the original value
		if decodedValue != value {
			t.Fatalf("Decoded value %d does not match original value %d", decodedValue, value)
		}

		// Check that the number of bytes read matches the number of bytes written
		if bytesRead != bytesWritten {
			t.Fatalf("Bytes read %d does not match bytes written %d", bytesRead, bytesWritten)
		}

		// To further ensure integrity, check if re-encoding produces the same result
		reencodedBuf := make([]byte, 8)
		reencodedBytesWritten, err := EncodeVaruint64(decodedValue, reencodedBuf, 0)
		if err != nil {
			t.Fatalf("Re-encoding failed: %v", err)
		}

		if reencodedBytesWritten != bytesWritten || !bytes.Equal(buf[:bytesWritten], reencodedBuf[:reencodedBytesWritten]) {
			t.Fatalf("Re-encoded bytes %v do not match original encoded bytes %v", reencodedBuf[:reencodedBytesWritten], buf[:bytesWritten])
		}
	})
}
