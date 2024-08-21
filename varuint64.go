/*
 *                        Varuint64 - Variable Length Encoding
 *
 * This file provides functions to encode and decode unsigned 64-bit integers into
 * a variable-length byte format, efficiently utilizing space based on the magnitude
 * of the integer. The header for encoding the length is 2 bits.
 *
 * EncodeVaruint64: Encodes an unsigned 64-bit integer into a variable-length format
 * and stores it into a byte buffer. The number of bytes used depends on the size of
 * the integer:
 *
 * - 1 byte  for values up to 2^6-1
 * - 2 bytes for values up to 2^14-1
 * - 4 bytes for values up to 2^30-1
 * - 8 bytes for values up to 2^62-1
 *
 * DecodeVaruint64: Decodes a variable-length encoded unsigned 64-bit integer from a
 * byte buffer starting at a given offset. The function returns the decoded integer,
 * the number of bytes consumed, and any error encountered during decoding.
 *
 * Error Handling: Both encoding and decoding functions include error checks to ensure
 * that the provided buffer is sufficiently large to store or retrieve the data.
 *
 * Usage Example:
 *     buf := make([]byte, 8)
 *     n := uint64(12345)
 *     encodedBytes, err := EncodeVaruint64(n, buf, 0)
 *      if err != nil {
 *          // handle error
 *      }
 *      decodedValue, bytesConsumed, err := DecodeVaruint64(buf, 0)
 *      if err != nil {
 *          // handle error
 *      }
 *
 * Encoding example:
 * +---------+---------+----------+
 * | Header  |  Data   |  Data    |
 * +---------+---------+----------+
 * |    01   | 000001  | 00110100 |
 * | (2bits) | (6bits) | (8bits)  |
 * +---------+---------+----------+
 *
 * - The header consists of 2 bits indicating the size (01 for 2-byte value),
 *   followed by the 6 most significant bits of the actual value.
 * - The next byte contains the remaining 8 bits of the value.
 *
 * Example:
 * If the value is 0x1234 (4660 in decimal):
 *
 * 1. Binary representation: 0001 0010 0011 0100
 * 2. Split into two parts:
 *   - Header: 01000001 (01 for 2-byte indicator, and 0010 for the 6 MSBs)
 *   - Data:   0011 0100 (the remaining 8 bits)
 *
 * Encoding:
 *  +----------+----------+
 *  | 01000001 | 00110100 |
 *  +----------+----------+
 * Resulting encoded bytes: 0x41 0x34
 */

package tomtp

import (
	"fmt"
)

func EncodeVaruint64(n uint64, buf []byte, offset int) (int, error) {
	bufLen := len(buf)

	switch {
	case n <= 0x3F:
		if bufLen < offset+1 {
			return 0, fmt.Errorf("buffer too small for encoding 1-byte varuint")
		}
		buf[offset] = byte(n)
		return 1, nil
	case n <= 0x3FFF:
		if bufLen < offset+2 {
			return 0, fmt.Errorf("buffer too small for encoding 2-byte varuint")
		}
		buf[offset+0] = byte(n>>8) | 0b01000000
		buf[offset+1] = byte(n)
		return 2, nil
	case n <= 0x3FFFFFFF:
		if bufLen < offset+4 {
			return 0, fmt.Errorf("buffer too small for encoding 4-byte varuint")
		}
		buf[offset+0] = byte(n>>24) | 0b10000000
		buf[offset+1] = byte(n >> 16)
		buf[offset+2] = byte(n >> 8)
		buf[offset+3] = byte(n)
		return 4, nil
	case n <= 0x3FFFFFFFFFFFFFFF:
		if bufLen < offset+8 {
			return 0, fmt.Errorf("buffer too small for encoding 8-byte varuint")
		}
		buf[offset+0] = byte(n>>56) | 0b11000000
		buf[offset+1] = byte(n >> 48)
		buf[offset+2] = byte(n >> 40)
		buf[offset+3] = byte(n >> 32)
		buf[offset+4] = byte(n >> 24)
		buf[offset+5] = byte(n >> 16)
		buf[offset+6] = byte(n >> 8)
		buf[offset+7] = byte(n)
		return 8, nil
	default:
		return 0, fmt.Errorf("unsupported varuint size of more than 62bits")
	}
}

func DecodeVaruint64(buf []byte, offset int) (uint64, int, error) {
	bufLen := len(buf)
	if bufLen < offset+1 {
		return 0, 0, fmt.Errorf("buffer too small for 1-byte varuint")
	}
	header := buf[offset] & 0b11000000

	switch header {
	case 0b00000000:
		return uint64(buf[offset] & 0x3F), 1, nil
	case 0b01000000:
		if bufLen < offset+2 {
			return 0, 0, fmt.Errorf("buffer too small for decoding 2-byte varuint")
		}
		return (uint64(buf[offset+0])&0x3F)<<8 |
				uint64(buf[offset+1]),
			2, nil
	case 0b10000000:
		if bufLen < offset+4 {
			return 0, 0, fmt.Errorf("buffer too small for decoding 4-byte varuint")
		}
		return (uint64(buf[offset+0])&0x3F)<<24 |
				uint64(buf[offset+1])<<16 |
				uint64(buf[offset+2])<<8 |
				uint64(buf[offset+3]),
			4, nil
	//case 0b11000000:
	default:
		if bufLen < offset+8 {
			return 0, 0, fmt.Errorf("buffer too small for decoding 8-byte varuint")
		}
		return (uint64(buf[offset+0])&0x3F)<<56 |
				uint64(buf[offset+1])<<48 |
				uint64(buf[offset+2])<<40 |
				uint64(buf[offset+3])<<32 |
				uint64(buf[offset+4])<<24 |
				uint64(buf[offset+5])<<16 |
				uint64(buf[offset+6])<<8 |
				uint64(buf[offset+7]),
			8, nil
	}
}
