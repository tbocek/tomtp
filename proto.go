package tomtp

import (
	"errors"
)

const (
	NoClose CloseOp = iota
	CloseStream
	CloseConnection

	FlagAckShift    = 0
	FlagSenderShift = 1 // bit 3 for Sender/Receiver
	FlagCloseShift  = 2 // bits 6-7 for close flags
	FlagCloseMask   = 0x3

	MinProtoSize = 13
)

type CloseOp uint8

var (
	ErrPayloadTooSmall = errors.New("payload Size below minimum of 8 bytes")
)

type PayloadMeta struct {
	CloseOp      CloseOp
	IsSender     bool
	Ack          *Ack
	RcvWndSize   uint64
	StreamId     uint32
	StreamOffset uint64
}

type Ack struct {
	StreamId     uint32
	StreamOffset uint64
	Len          uint16
}

func GetCloseOp(streamClose bool, connClose bool) CloseOp {
	switch {
	case connClose:
		return CloseConnection
	case streamClose:
		return CloseStream
	default:
		return NoClose
	}
}

func CalcProtoOverhead(ack bool) int {
	overhead := 1 //header Size
	if ack {
		overhead += 8         // RcvWndSize (64-bit)
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

	// Set close flags
	flags |= uint8(p.CloseOp) << FlagCloseShift

	// Write header
	encoded[offset] = flags
	offset++

	// Write ACKs section if present
	if p.Ack != nil {
		PutUint64(encoded[offset:], p.RcvWndSize)
		offset += 8

		// Write ACKs
		PutUint32(encoded[offset:], p.Ack.StreamId)
		offset += 4

		PutUint64(encoded[offset:], p.Ack.StreamOffset)
		offset += 8

		PutUint16(encoded[offset:], p.Ack.Len)
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
	payload.CloseOp = CloseOp((flags >> FlagCloseShift) & FlagCloseMask)

	// Decode ACKs if present
	if ack {
		if offset+8+4+8+2 > dataLen {
			return nil, 0, nil, ErrPayloadTooSmall
		}

		payload.RcvWndSize = Uint64(data[offset:])
		offset += 8

		payload.Ack = &Ack{}
		payload.Ack.StreamId = Uint32(data[offset:])
		offset += 4

		payload.Ack.StreamOffset = Uint64(data[offset:])
		offset += 8

		payload.Ack.Len = Uint16(data[offset:])
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
