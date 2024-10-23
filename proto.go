package tomtp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
)

type Payload struct {
	StreamId   uint32
	CloseFlag  bool
	RcvWndSize uint64
	AckSn      uint64
	Data       []byte
}

func EncodePayload(
	streamId uint32,
	closeFlag bool,
	rcvWndSize uint64,
	ackSn uint64,
	data []byte,
	w io.Writer) (n int, err error) {

	buf := new(bytes.Buffer)

	// STREAM_ID (32-bit)
	if err := binary.Write(buf, binary.BigEndian, streamId); err != nil {
		return 0, err
	}

	// Combine the close flag with the RCV_WND_SIZE
	if closeFlag {
		rcvWndSize |= 0x8000000000000000 // Set the highest bit to 1
	}
	// RCV_WND_SIZE (63 bits) + STREAM_CLOSE_FLAG (1 bit)
	if err := binary.Write(buf, binary.BigEndian, rcvWndSize); err != nil {
		return 0, err
	}

	// ACK (64-bit)
	if err := binary.Write(buf, binary.BigEndian, ackSn); err != nil {
		return 0, err
	}

	// Write DATA if present
	if len(data) > 0 {
		if _, err := buf.Write(data); err != nil {
			return 0, err
		}
	}

	n, err = w.Write(buf.Bytes())
	return n, err
}

func DecodePayload(buf *bytes.Buffer) (payload *Payload, err error) {
	payload = &Payload{}
	//bytesRead := 0

	// Helper function to read bytes and keep track of the count
	readBytes := func(num int) ([]byte, error) {
		if num > buf.Len() {
			return nil, errors.New("Attempted to read " + strconv.Itoa(num) + " bytes when only " + strconv.Itoa(buf.Len()) + " remaining")
		}
		b := make([]byte, num)
		_, err := io.ReadFull(buf, b)
		if err != nil {
			return nil, err
		}
		return b, nil
	}

	// STREAM_ID (32-bit)
	streamIdBytes, err := readBytes(4)
	if err != nil {
		return nil, err
	}
	payload.StreamId = binary.BigEndian.Uint32(streamIdBytes)

	// RCV_WND_SIZE + STREAM_CLOSE_FLAG (64-bit)
	rcvWndSizeBytes, err := readBytes(8)
	if err != nil {
		return nil, err
	}
	rcvWndSize := binary.BigEndian.Uint64(rcvWndSizeBytes)
	payload.CloseFlag = (rcvWndSize & 0x8000000000000000) != 0 // Extract the STREAM_CLOSE_FLAG
	payload.RcvWndSize = rcvWndSize & 0x7FFFFFFFFFFFFFFF       // Mask out the close flag to get the actual RCV_WND_SIZE

	// ACK_START_SN (64-bit)
	ackSnBytes, err := readBytes(8)
	if err != nil {
		return nil, err
	}
	payload.AckSn = binary.BigEndian.Uint64(ackSnBytes)

	// Read the remaining data
	remainingBytes := buf.Len()
	if remainingBytes > 0 {
		payload.Data = make([]byte, remainingBytes)
		_, err = io.ReadFull(buf, payload.Data)
		if err != nil {
			return nil, err
		}
	}

	return payload, nil
}
