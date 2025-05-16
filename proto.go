package tomtp

import (
	"errors"
)

const (
	FlagAckShift    = 0
	FlagSenderShift = 1
	FlagCloseShift  = 2

	MinProtoSize = 13
)

var (
	ErrPayloadTooSmall = errors.New("payload Size below minimum of 8 bytes")
)

type PayloadMeta struct {
	IsClose      bool
	IsSender     bool
	Ack          *Ack
	RcvWndSize   uint64
	StreamId     uint32
	StreamOffset uint64
}

type Ack struct {
	streamId uint32
	offset   uint64
	len      uint16
}

func CalcProtoOverhead(ack bool) int {
	overhead := 1 //header Size
	overhead += 8 // RcvWndSize (64-bit)
	if ack {
		overhead += 4 + 8 + 2 // StreamId, StreamOffset (64-bit), Len
	}
	overhead += 4 // StreamId
	overhead += 8 // StreamOffset (64-bit)
	// now comes the data... -> but not calculated in overhead
	return overhead
}

func EncodePayload(p *PayloadMeta, payloadData []byte) (encoded []byte, offset int, err error) {

	// Calculate total Size
	size := CalcProtoOverhead(p.Ack != nil) + len(payloadData)

	// Allocate buffer
	encoded = make([]byte, size)

	// Calculate flags
	var flags uint8
	if p.Ack != nil {
		flags = 1 << FlagAckShift //its 0, but for the sake of readability / completeness
	}

	if p.IsSender {
		flags |= 1 << FlagSenderShift
	}

	if p.IsClose {
		flags |= 1 << FlagCloseShift
	}

	// Write header
	encoded[offset] = flags
	offset++

	PutUint64(encoded[offset:], p.RcvWndSize)
	offset += 8

	// Write ACKs section if present
	if p.Ack != nil {
		// Write ACKs
		PutUint32(encoded[offset:], p.Ack.streamId)
		offset += 4

		PutUint64(encoded[offset:], p.Ack.offset)
		offset += 8

		PutUint16(encoded[offset:], p.Ack.len)
		offset += 2
	}

	// Write Data
	PutUint32(encoded[offset:], p.StreamId)
	offset += 4

	PutUint64(encoded[offset:], p.StreamOffset)
	offset += 8

	dataLen := uint16(len(payloadData))
	if dataLen > 0 {
		copy(encoded[offset:], payloadData)
		offset += int(dataLen)
	}

	return encoded, offset, nil
}

func DecodePayload(data []byte) (payload *PayloadMeta, offset int, payloadData []byte, err error) {
	dataLen := len(data)
	if dataLen < MinProtoSize {
		return nil, 0, nil, ErrPayloadTooSmall
	}

	offset = 0
	payload = &PayloadMeta{}

	// Flags (8 bits)
	flags := data[offset]
	offset++

	ack := (flags & (1 << FlagAckShift)) != 0
	payload.IsSender = (flags & (1 << FlagSenderShift)) != 0
	payload.IsClose = (flags & (1 << FlagCloseShift)) != 0

	payload.RcvWndSize = Uint64(data[offset:])
	offset += 8

	// Decode ACKs if present
	if ack {
		if offset+4+8+2 > dataLen {
			return nil, 0, nil, ErrPayloadTooSmall
		}

		payload.Ack = &Ack{}
		payload.Ack.streamId = Uint32(data[offset:])
		offset += 4

		payload.Ack.offset = Uint64(data[offset:])
		offset += 8

		payload.Ack.len = Uint16(data[offset:])
		offset += 2
	}

	// Decode Data
	if offset+4 > dataLen {
		return nil, 0, nil, ErrPayloadTooSmall
	}
	payload.StreamId = Uint32(data[offset:])
	offset += 4

	if offset+8 > dataLen {
		return nil, 0, nil, ErrPayloadTooSmall
	}
	payload.StreamOffset = Uint64(data[offset:])
	offset += 8

	if dataLen > offset {
		payloadData = make([]byte, dataLen-offset)
		copy(payloadData, data[offset:dataLen])
		offset += dataLen
	} else {
		payloadData = make([]byte, 0)
	}

	return payload, offset, payloadData, nil
}
