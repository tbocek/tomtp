package tomtp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const (
	PayloadVersion   uint8 = 0
	MinPayloadSize         = 8
	StreamFlagClose        = 1 << 0
	StreamFlagRcvWnd       = 1 << 1
	StreamFlagAckSn        = 1 << 2
	StreamFlagData         = 1 << 3
)

var (
	ErrPayloadTooSmall = errors.New("payload size below minimum of 8 bytes")
)

type Payload struct {
	Version    uint8
	Length     uint16
	StreamId   uint32
	CloseFlag  bool
	RcvWndSize uint64 // Only 48 bits used
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

	// Initialize flags
	var flags uint8
	if closeFlag {
		flags |= StreamFlagClose
	}

	// Version (8 bits)
	if err := buf.WriteByte(PayloadVersion); err != nil {
		return 0, err
	}

	// Length (16 bits) - calculated based on payload content
	payloadLen := uint16(8) // minimum size
	if rcvWndSize != 0 {
		payloadLen += 6 // 48-bit window size
		flags |= StreamFlagRcvWnd
	}
	if ackSn != 0 {
		payloadLen += 8 // 64-bit ACK
		flags |= StreamFlagAckSn
	}
	if len(data) > 0 {
		payloadLen += uint16(len(data))
		flags |= StreamFlagData
	}

	if err := binary.Write(buf, binary.BigEndian, payloadLen); err != nil {
		return 0, err
	}

	// StreamId (32 bits)
	if err := binary.Write(buf, binary.BigEndian, streamId); err != nil {
		return 0, err
	}

	// Flags (8 bits)
	if err := buf.WriteByte(flags); err != nil {
		return 0, err
	}

	// Optional RcvWndSize (48 bits)
	if rcvWndSize != 0 {
		// Write only 6 bytes (48 bits)
		wndBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(wndBytes, rcvWndSize&0x0000FFFFFFFFFFFF)
		if _, err := buf.Write(wndBytes[2:8]); err != nil {
			return 0, err
		}
	}

	// Optional AckSn (64 bits)
	if ackSn != 0 {
		if err := binary.Write(buf, binary.BigEndian, ackSn); err != nil {
			return 0, err
		}
	}

	// Optional Data
	if len(data) > 0 {
		if _, err := buf.Write(data); err != nil {
			return 0, err
		}
	}

	n, err = w.Write(buf.Bytes())
	return n, err
}

func DecodePayload(buf *bytes.Buffer) (payload *Payload, err error) {
	if buf.Len() < MinPayloadSize {
		return nil, ErrPayloadTooSmall
	}

	payload = &Payload{}
	bytesRead := 8

	// Version (8 bits)
	version, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	payload.Version = version

	// Length (16 bits)
	if err := binary.Read(buf, binary.BigEndian, &payload.Length); err != nil {
		return nil, err
	}

	// StreamId (32 bits)
	if err := binary.Read(buf, binary.BigEndian, &payload.StreamId); err != nil {
		return nil, err
	}

	// Flags (8 bits)
	flags, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}

	if flags&StreamFlagClose != 0 {
		payload.CloseFlag = true
	}

	// Optional RcvWndSize (48 bits)
	if flags&StreamFlagRcvWnd != 0 {
		wndBytes := make([]byte, 8)
		if _, err := buf.Read(wndBytes[2:]); err != nil { // Read 6 bytes
			return nil, err
		}
		payload.RcvWndSize = binary.BigEndian.Uint64(wndBytes) & 0x0000FFFFFFFFFFFF
		bytesRead += 6
	}

	// Optional AckSn (64 bits)
	if flags&StreamFlagAckSn != 0 {
		if err := binary.Read(buf, binary.BigEndian, &payload.AckSn); err != nil {
			return nil, err
		}
		bytesRead += 8
	}

	// Optional Data
	if flags&StreamFlagData != 0 {
		dataLen := int(payload.Length) - bytesRead
		if dataLen > 0 {
			payload.Data = make([]byte, dataLen)
			if _, err := io.ReadFull(buf, payload.Data); err != nil {
				return nil, err
			}
		}
	}

	return payload, nil
}
