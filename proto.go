package tomtp

import (
	"errors"
	"math"
)

const (
	NoClose CloseOp = iota
	CloseStream
	CloseConnection

	uint32Max = math.MaxUint32

	FlagAckMask     = 0x7 // bits 0-2 for ACK count (0-7)
	FlagSenderShift = 3   // bit 3 for Sender/Receiver
	FlagFillShift   = 4   // bit 4 for Fill presence
	FlagLrgShift    = 5   // bit 5 for large offsets
	FlagCloseShift  = 6   // bits 6-7 for close flags
	FlagCloseMask   = 0x3
)

type CloseOp uint8

var (
	ErrPayloadTooSmall = errors.New("payload size below minimum of 8 bytes")
	ErrInvalidAckCount = errors.New("invalid ACK count")
)

type Payload struct {
	CloseOp      CloseOp
	IsSender     bool
	Acks         []Ack
	RcvWndSize   uint64
	FillerLen    uint16
	StreamId     uint32
	StreamOffset uint64
	Data         []byte
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

func CalcOverhead(p *Payload) int {
	size := 1 //header size

	if p.Acks != nil {
		size += 1 // IsAcksLargeOffset

		// RcvWndSize size depends on its value
		if p.RcvWndSize > uint32Max {
			size += 8 // RcvWndSize (64-bit)
		} else {
			size += 4 // RcvWndSize (32-bit)
		}

		for _, ack := range p.Acks {
			size += 4 // StreamId
			if ack.StreamOffset > uint32Max {
				size += 8 // StreamOffset (64-bit)
			} else {
				size += 4 // StreamOffset (32-bit)
			}
			size += 2 // Len
		}
	}

	if p.FillerLen > 0 {
		size += 2                // FillerLen
		size += int(p.FillerLen) // Zero filler bytes
	}

	size += 4 // StreamId
	if p.StreamOffset > uint32Max {
		size += 8 // StreamOffset (64-bit)
	} else {
		size += 4 // StreamOffset (32-bit)
	}
	size += 2           // Data length
	size += len(p.Data) // Data

	return size
}

func EncodePayload(p *Payload) (encoded []byte, offset int, err error) {
	if p.Acks != nil && len(p.Acks) > 7 {
		return nil, 0, errors.New("too many Acks")
	}

	// Calculate total size
	size := CalcOverhead(p)

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
	if p.FillerLen > 0 {
		flags |= 1 << FlagFillShift
	}
	if p.StreamOffset > uint32Max {
		flags |= 1 << FlagLrgShift
	}

	// Set close flags
	flags |= uint8(p.CloseOp) << FlagCloseShift

	// Write header
	encoded[offset] = flags
	offset++

	// Write ACKs section if present
	if p.Acks != nil {
		// Calculate ACK flags byte
		var ackFlags uint8
		if p.RcvWndSize > uint32Max {
			ackFlags |= 0x1 // Set RcvWndSize size flag (bit 0)
		}
		for i, ack := range p.Acks {
			if ack.StreamOffset > uint32Max {
				ackFlags |= 1 << (i + 1) // Set ACK offset size flag (bits 1-7)
			}
		}

		// Write ACK flags
		encoded[offset] = ackFlags
		offset++

		// Write RcvWndSize based on its value
		if p.RcvWndSize > uint32Max {
			PutUint64(encoded[offset:], p.RcvWndSize)
			offset += 8
		} else {
			PutUint32(encoded[offset:], uint32(p.RcvWndSize))
			offset += 4
		}

		// Write ACKs
		for _, ack := range p.Acks {
			PutUint32(encoded[offset:], ack.StreamId)
			offset += 4

			if ack.StreamOffset > uint32Max {
				PutUint64(encoded[offset:], ack.StreamOffset)
				offset += 8
			} else {
				PutUint32(encoded[offset:], uint32(ack.StreamOffset))
				offset += 4
			}

			PutUint16(encoded[offset:], ack.Len)
			offset += 2
		}
	}

	// Write Filler if present
	if p.FillerLen > 0 {
		PutUint16(encoded[offset:], p.FillerLen)
		offset += 2
		// Fill with zeros - make automatically zeros the slice
		clear(encoded[offset : offset+int(p.FillerLen)])
		offset += int(p.FillerLen)
	}

	// Write Data
	PutUint32(encoded[offset:], p.StreamId)
	offset += 4

	if p.StreamOffset > uint32Max {
		PutUint64(encoded[offset:], p.StreamOffset)
		offset += 8
	} else {
		PutUint32(encoded[offset:], uint32(p.StreamOffset))
		offset += 4
	}
	dataLen := uint16(len(p.Data))
	PutUint16(encoded[offset:], dataLen)
	offset += 2
	if dataLen > 0 {
		copy(encoded[offset:], p.Data)
		offset += int(dataLen)
	}

	return encoded, offset, nil
}

func DecodePayload(data []byte) (payload *Payload, offset int, err error) {
	if len(data) < MinPayloadSize {
		return nil, 0, ErrPayloadTooSmall
	}

	offset = 0
	payload = &Payload{}

	// Flags (8 bits)
	flags := data[offset]
	offset++

	ackCount := flags & FlagAckMask
	payload.IsSender = (flags & (1 << FlagSenderShift)) != 0
	hasFiller := (flags & (1 << FlagFillShift)) != 0
	isDataLargeOffset := (flags & (1 << FlagLrgShift)) != 0

	payload.CloseOp = CloseOp((flags >> FlagCloseShift) & FlagCloseMask)

	// Decode ACKs if present
	if ackCount > 0 {
		// Read ACK flags
		ackFlags := data[offset]
		offset++

		// Read RcvWndSize based on flag
		if ackFlags&0x1 != 0 {
			payload.RcvWndSize = Uint64(data[offset:])
			offset += 8
		} else {
			payload.RcvWndSize = uint64(Uint32(data[offset:]))
			offset += 4
		}

		// Read ACKs
		payload.Acks = make([]Ack, ackCount)
		for i := 0; i < int(ackCount); i++ {
			ack := Ack{}
			ack.StreamId = Uint32(data[offset:])
			offset += 4

			if ackFlags&(1<<(i+1)) != 0 {
				ack.StreamOffset = Uint64(data[offset:])
				offset += 8
			} else {
				ack.StreamOffset = uint64(Uint32(data[offset:]))
				offset += 4
			}

			ack.Len = Uint16(data[offset:])
			offset += 2
			payload.Acks[i] = ack
		}
	}

	// Decode Filler if present
	if hasFiller {
		payload.FillerLen = Uint16(data[offset:])
		offset += 2
		// Skip filler bytes (they're all zeros)
		offset += int(payload.FillerLen)
	}

	// Decode Data
	payload.StreamId = Uint32(data[offset:])
	offset += 4

	if isDataLargeOffset {
		payload.StreamOffset = Uint64(data[offset:])
		offset += 8
	} else {
		payload.StreamOffset = uint64(Uint32(data[offset:]))
		offset += 4
	}

	dataLen := Uint16(data[offset:])
	offset += 2

	if dataLen > 0 {
		payload.Data = make([]byte, dataLen)
		copy(payload.Data, data[offset:offset+int(dataLen)])
		offset += int(dataLen)
	} else {
		payload.Data = make([]byte, 0)
	}

	return payload, offset, nil
}
