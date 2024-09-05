package tomtp

/*
RLE in golang with the following rules to dynamically encode the length, so that short length use fewer bits.
The maximum length of the input arary is 32 bit.

The length encoding, where x is used to encode the length

                                 1xx ->  2 bits for length. (length 1-4)
                              1xx0xx ->  4 bits for length. (length 5-12)
                        1xxxxx0xx0xx ->  8 bits for length. (length 13-268)
               1xxxxxxxx0xxxxx0xx0xx -> 16 bits for length. (length 269-65804)
xxxxxxxxxxxxxxx0xxxxxxxx0xxxxx0xx0xx -> 32 bits for length. (length 0-2^32-1)

if array is short, fill rest with 0 until 32bit. The least siginficant bit is left

Assume the following examples that has a startbit of 1
111 -> 4 x '1' (1111)
111111 -> 4 x '1', 4x '0' (11110000)
011111111 -> 8x '1' 4x '0' (111111110000)

use the following functions:

encode(startbit bool, input []data) (output []data)
and
decode(startbit bool, input []data) (output []data)
*/

import (
	"math/bits"
)

func EncodeRLE(input []uint32) (uint64, bool) {
	bs := New(0)
	n := 0

	var isNotFull bool
	for _, length := range input {
		n, isNotFull = EncodeLength(length, bs, n)
		if !isNotFull {
			break
		}
	}
	return bs.BitSet(), !isNotFull
}

func EncodeLength(length uint32, bs *BitSet, n int) (int, bool) {
	switch {
	case length <= 4: // 2 bits for length
		if maxBits-n < 3 {
			break
		}
		length = length - 1

		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, 1)
		n++

		return n, true
	case length <= 12: // 4 bits for length
		if maxBits-n < 6 {
			break
		}
		length = length - 5

		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, 0)
		n++

		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, 1)
		n++

		return n, true
	case length <= 268: // 8 bits for length
		if maxBits-n < 11 {
			break
		}
		length = length - 13

		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, 0)
		n++

		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, 0)
		n++

		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, 1)
		n++

		return n, true
	case length <= 65804: // 16 bits for length
		if maxBits-n < 20 {
			break
		}
		length = length - 269

		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, 0)
		n++

		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, 0)
		n++

		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, 0)
		n++

		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, length&1)
		n++
		length = length >> 1
		bs.Set(n, 1)
		n++
		return n, true
	}

	// 32 bits for length
	bitsNeeded := bits.Len32(length)
	if bitsNeeded > 2 {
		bitsNeeded++
	}
	if bitsNeeded > 5 {
		bitsNeeded++
	}
	if bitsNeeded > 10 {
		bitsNeeded++
	}
	if bitsNeeded > 18 {
		bitsNeeded++
	}
	if (maxBits - n) < bitsNeeded {
		return n, false
	}

	for i := 0; i < 2; i++ {
		bs.Set(n, length&1)
		n++
		if n == maxBits {
			return n, true
		}
		length = length >> 1
	}

	bs.Set(n, 0)
	n++
	if n == maxBits {
		return n, true
	}

	for i := 0; i < 2; i++ {
		bs.Set(n, length&1)
		n++
		if n == maxBits {
			return n, true
		}
		length = length >> 1
	}

	bs.Set(n, 0)
	n++
	if n == maxBits {
		return n, true
	}

	for i := 0; i < 4; i++ {
		bs.Set(n, length&1)
		n++
		if n == maxBits {
			return n, true
		}
		length = length >> 1
	}

	bs.Set(n, 0)
	n++
	if n == maxBits {
		return n, true
	}

	for i := 0; i < 8; i++ {
		bs.Set(n, length&1)
		n++
		if n == maxBits {
			return n, true
		}
		length = length >> 1
	}

	bs.Set(n, 0)
	n++
	if n == maxBits {
		return n, true
	}

	for i := 0; i < 16; i++ {
		bs.Set(n, length&1)
		n++
		if n == maxBits {
			return n, true
		}
		length = length >> 1
	}

	return n, true
}

func DecodeRLE(encoded uint64) []uint32 {
	bs := New(encoded)
	n := 0
	output := []uint32{}

	for n < bs.Len() {
		var length uint32
		if bs.Test(n + 2) { // Check if it's a 2-bit length (xx1)
			length = 1 + (bs.TestInt(n + 0)) + ((bs.TestInt(n + 1)) << 1)
			n += 3
		} else if bs.Test(n + 5) { // Check if it's a 4-bit length (xx0xx1)
			length = 5 + (bs.TestInt(n + 0)) + ((bs.TestInt(n + 1)) << 1) + ((bs.TestInt(n + 3)) << 2) + ((bs.TestInt(n + 4)) << 3)
			n += 6
		} else if bs.Test(n + 10) { // Check if it's an 8-bit length (xx0xx0xxxx1)
			length = 13 + (bs.TestInt(n + 0)) + ((bs.TestInt(n + 1)) << 1) + ((bs.TestInt(n + 3)) << 2) + ((bs.TestInt(n + 4)) << 3) +
				((bs.TestInt(n + 6)) << 4) + ((bs.TestInt(n + 7)) << 5) + ((bs.TestInt(n + 8)) << 6) + ((bs.TestInt(n + 9)) << 7)
			n += 11
		} else if bs.Test(n + 19) { // Check if it's a 16-bit length (xx0xx0xxxx0xxxxxxxx1)
			length = 269 + (bs.TestInt(n + 0)) + ((bs.TestInt(n + 1)) << 1) + ((bs.TestInt(n + 3)) << 2) + ((bs.TestInt(n + 4)) << 3) +
				((bs.TestInt(n + 6)) << 4) + ((bs.TestInt(n + 7)) << 5) + ((bs.TestInt(n + 8)) << 6) + ((bs.TestInt(n + 9)) << 7) +
				((bs.TestInt(n + 11)) << 8) + ((bs.TestInt(n + 12)) << 9) + ((bs.TestInt(n + 13)) << 10) + ((bs.TestInt(n + 14)) << 11) +
				((bs.TestInt(n + 15)) << 12) + ((bs.TestInt(n + 16)) << 13) + ((bs.TestInt(n + 17)) << 14) + ((bs.TestInt(n + 18)) << 15)
			n += 20
		} else { // Check if it's a 32-bit length (xx0xx0xxxx0xxxxxxxx0xxxxxxxxxxxxxxx)
			length = (bs.TestInt(n + 0)) + ((bs.TestInt(n + 1)) << 1) + ((bs.TestInt(n + 3)) << 2) + ((bs.TestInt(n + 4)) << 3) +
				((bs.TestInt(n + 6)) << 4) + ((bs.TestInt(n + 7)) << 5) + ((bs.TestInt(n + 8)) << 6) + ((bs.TestInt(n + 9)) << 7) +
				((bs.TestInt(n + 11)) << 8) + ((bs.TestInt(n + 12)) << 9) + ((bs.TestInt(n + 13)) << 10) + ((bs.TestInt(n + 14)) << 11) +
				((bs.TestInt(n + 15)) << 12) + ((bs.TestInt(n + 16)) << 13) + ((bs.TestInt(n + 17)) << 14) + ((bs.TestInt(n + 18)) << 15) +
				((bs.TestInt(n + 20)) << 16) + ((bs.TestInt(n + 21)) << 17) + ((bs.TestInt(n + 22)) << 18) + ((bs.TestInt(n + 23)) << 19) +
				((bs.TestInt(n + 24)) << 20) + ((bs.TestInt(n + 25)) << 21) + ((bs.TestInt(n + 26)) << 22) + ((bs.TestInt(n + 27)) << 23) +
				((bs.TestInt(n + 28)) << 24) + ((bs.TestInt(n + 29)) << 25) + ((bs.TestInt(n + 30)) << 26) + ((bs.TestInt(n + 31)) << 27)
			n += 32
		}
		if length == 0 {
			return output
		}
		output = append(output, length)
	}
	return output
}
