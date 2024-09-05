package tomtp

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
	"time"
)

func TestEncode1(t *testing.T) {
	inputArray := []uint32{4}
	encoded, isFull := EncodeRLE(inputArray)
	fmt.Printf("Encoded (%v) : %064b\n", isFull, encoded)
	outputArray := DecodeRLE(encoded)
	assert.Equal(t, inputArray, outputArray)
}

func TestEncode2(t *testing.T) {
	inputArray := []uint32{4, 5}
	encoded, isFull := EncodeRLE(inputArray)
	fmt.Printf("Encoded (%v) : %064b\n", isFull, encoded)
	outputArray := DecodeRLE(encoded)
	assert.Equal(t, inputArray, outputArray)
}

func TestEncodeMax1(t *testing.T) {
	inputArray := []uint32{0xff}
	encoded, isFull := EncodeRLE(inputArray)
	fmt.Printf("Input: %v\nEncoded: %064b (isFull: %v)\n", inputArray, encoded, isFull)
	outputArray := DecodeRLE(encoded)
	assert.Equal(t, inputArray, outputArray)
}

func TestEncodeMax2(t *testing.T) {
	inputArray := []uint32{268}
	encoded, isFull := EncodeRLE(inputArray)
	fmt.Printf("Input: %v\nEncoded: %064b (isFull: %v)\n", inputArray, encoded, isFull)
	outputArray := DecodeRLE(encoded)
	assert.Equal(t, inputArray, outputArray)
}

func TestEncodeMax3(t *testing.T) {
	inputArray := []uint32{268, 268, 268, 268, 268, 268}
	encoded, isFull := EncodeRLE(inputArray)
	fmt.Printf("Input: %v\nEncoded: %064b (isFull: %v)\n", inputArray, encoded, isFull)
	outputArray := DecodeRLE(encoded)
	if !isFull {
		assert.Equal(t, inputArray, outputArray)
	} else {
		assert.Equal(t, true, isPrefix(inputArray, outputArray))
	}
	assert.Equal(t, true, isFull)
}

func TestEncodeMax4(t *testing.T) {
	inputArray := []uint32{268, 268, 268, 268, 268, 14}
	encoded, isFull := EncodeRLE(inputArray)
	fmt.Printf("Input: %v\nEncoded: %064b (isFull: %v)\n", inputArray, encoded, isFull)
	outputArray := DecodeRLE(encoded)
	fmt.Printf("Outpt: %v\n", outputArray)
	if !isFull {
		assert.Equal(t, inputArray, outputArray)
	} else {
		assert.Equal(t, true, isPrefix(inputArray, outputArray))
	}
	assert.Equal(t, false, isFull)
}

func TestEncodeMax5(t *testing.T) {
	inputArray := []uint32{268, 268, 268, 268, 268, 0x3f}
	encoded, isFull := EncodeRLE(inputArray)
	fmt.Printf("Input: %v\nEncoded: %064b (isFull: %v)\n", inputArray, encoded, isFull)
	outputArray := DecodeRLE(encoded)
	fmt.Printf("Outpt: %v\n", outputArray)
	if !isFull {
		assert.Equal(t, inputArray, outputArray)
	} else {
		assert.Equal(t, true, isPrefix(inputArray, outputArray))
	}
	assert.Equal(t, false, isFull)
}
func TestEncodeMax6(t *testing.T) {
	inputArray := []uint32{268, 268, 268, 268, 268, 0xff}
	encoded, isFull := EncodeRLE(inputArray)
	fmt.Printf("Input: %v\nEncoded: %064b (isFull: %v)\n", inputArray, encoded, isFull)
	outputArray := DecodeRLE(encoded)
	fmt.Printf("Outpt: %v\n", outputArray)
	if !isFull {
		assert.Equal(t, inputArray, outputArray)
	} else {
		assert.Equal(t, true, isPrefix(inputArray, outputArray))
	}
	assert.Equal(t, true, isFull)
}

func FuzzEncodeDecode(f *testing.F) {
	// Adding some seed corpus
	f.Add(uint32(1), uint32(4), uint32(5), uint32(268), uint32(0xff), uint32(0), uint32(0))
	f.Add(uint32(0), uint32(1), uint32(2), uint32(3), uint32(12), uint32(268), uint32(65804))
	f.Add(uint32(1), uint32(1), uint32(268), uint32(0xff), uint32(268), uint32(65804), uint32(0))

	// Setting a random seed for generating fuzzing inputs
	rand.Seed(time.Now().UnixNano())

	f.Fuzz(func(t *testing.T, startBit uint32, input1 uint32, input2 uint32, input3 uint32, input4 uint32, input5 uint32, input6 uint32) {
		var inputArray []uint32
		if input1 != 0 {
			inputArray = append(inputArray, input1)
			if input2 != 0 {
				inputArray = append(inputArray, input2)
				if input3 != 0 {
					inputArray = append(inputArray, input3)
					if input4 != 0 {
						inputArray = append(inputArray, input4)
						if input5 != 0 {
							inputArray = append(inputArray, input5)
							if input6 != 0 {
								inputArray = append(inputArray, input6)
							}
						}
					}
				}
			}
		}
		startBit = startBit & 1

		// Encode the input array
		encoded, isFull := EncodeRLE(inputArray)

		// Decode the encoded data
		outputArray := DecodeRLE(encoded)

		// If the buffer isn't full, the decoded output should match the input
		if !isFull {
			if !equalUintArrays(inputArray, outputArray) {
				t.Errorf("Round-trip Encode/Decode failed for input: %v\nEncoded: %064b\nDecoded: %v\n", inputArray, encoded, outputArray)
			}
		} else {
			// If the buffer is full, the original input may have been truncated in the encoded output.
			// Ensure that the decoded output is a prefix of the input array.
			if !isPrefix(inputArray, outputArray) {
				t.Errorf("Truncated Encode/Decode failed for input: %v\nEncoded: %064b\nDecoded: %v\n", inputArray, encoded, outputArray)
			}
		}
	})
}

func equalUintArrays(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isPrefix(a, b []uint32) bool {
	if len(b) > len(a) {
		return false
	}
	for i := range b {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
