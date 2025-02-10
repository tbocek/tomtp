package tomtp

import (
	"errors"
)

const (
	NoClose CloseOp = iota
	CloseStream
	CloseConnection

	FlagAckMask     = 0xf // bits 0-3 for ACK count (0-15)
	FlagSenderShift = 4   // bit 3 for Sender/Receiver
	FlagCloseShift  = 6   // bits 6-7 for close flags
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
	Acks         []Ack
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

func CalcProtoOverhead(ackLen int) int {
	overhead := 1 //header Size
	if ackLen > 0 {
		overhead += 8                    // RcvWndSize (64-bit)
		overhead += ackLen * (4 + 8 + 2) // StreamId, StreamOffset (64-bit), Len
	}
	overhead += 4 // StreamId
	overhead += 8 // StreamOffset (64-bit)
	// now comes the data... -> but not calculated in overhead
	return overhead
}

func EncodePayload(p *PayloadMeta, payloadData []byte) (encoded []byte, offset int, err error) {
	if p.Acks != nil && len(p.Acks) > 15 {
		return nil, 0, errors.New("too many Acks")
	}

	// Calculate total Size
	size := CalcProtoOverhead(len(p.Acks)) + len(payloadData)

	// Allocate buffer
	encoded = make([]byte, size)

	// Calculate flags
	var flags uint8
	if p.Acks != nil {
		flags = uint8(len(p.Acks)) & FlagAckMask // bits 0-2 for ACK count
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
	if p.Acks != nil {
		PutUint64(encoded[offset:], p.RcvWndSize)
		offset += 8

		// Write ACKs
		for _, ack := range p.Acks {
			PutUint32(encoded[offset:], ack.StreamId)
			offset += 4

			PutUint64(encoded[offset:], ack.StreamOffset)
			offset += 8

			PutUint16(encoded[offset:], ack.Len)
			offset += 2
		}
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

	ackCount := flags & FlagAckMask
	payload.IsSender = (flags & (1 << FlagSenderShift)) != 0
	payload.CloseOp = CloseOp((flags >> FlagCloseShift) & FlagCloseMask)

	// Decode ACKs if present
	if ackCount > 0 {
		if offset+8 > dataLen {
			return nil, 0, nil, ErrPayloadTooSmall
		}
		payload.RcvWndSize = Uint64(data[offset:])
		offset += 8

		// Read ACKs
		payload.Acks = make([]Ack, ackCount)
		for i := 0; i < int(ackCount); i++ {
			if offset+4+8+2 > dataLen {
				return nil, 0, nil, ErrPayloadTooSmall
			}
			ack := Ack{}
			ack.StreamId = Uint32(data[offset:])
			offset += 4

			ack.StreamOffset = Uint64(data[offset:])
			offset += 8

			ack.Len = Uint16(data[offset:])
			offset += 2
			payload.Acks[i] = ack
		}
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
