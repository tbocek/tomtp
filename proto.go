package tomtp

import (
	"errors"
)

const (
	PayloadMinSize = 5

	FlagAckMask         = 0xF // bits 0-3 for ACK count (0-15)
	StreamFlagClose     = 1 << 5
	CloseConnectionFlag = 1 << 5
	FlagFiller          = 1 << 6
	FlagRole            = 1 << 7
)

var (
	ErrPayloadTooSmall = errors.New("payload size below minimum of 8 bytes")
	ErrFillerTooLarge  = errors.New("filler length has limit of 65536")
	ErrInvalidAckCount = errors.New("invalid ACK count")
)

type Payload struct {
	StreamFlagClose     bool
	CloseConnectionFlag bool
	IsRecipient         bool
	RcvWndSize          uint32
	Acks                []Ack
	SnStream            uint64
	Filler              []byte
	Data                *Data
}

type Ack struct {
	StreamId     uint32
	StreamOffset uint64
	Len          uint16
}

type Data struct {
	StreamId     uint32
	StreamOffset uint64
	Data         []byte
}

func CalcOverhead(p *Payload) int {
	size := PayloadMinSize
	if p.Acks != nil {
		size += 4                         // RcvWndSize
		size += len(p.Acks) * (4 + 6 + 2) // ACK data (StreamId:4, StreamOffset:6, Len:2)
	}
	if p.Filler != nil {
		size += 2             // FillerLength
		size += len(p.Filler) // Filler data
	}
	if p.Data != nil {
		size += 4                // StreamId (32 bits)
		size += 6                // StreamOffset (48 bits)
		size += len(p.Data.Data) // Data
	}
	return size
}

func EncodePayload(p *Payload) ([]byte, error) {
	if len(p.Acks) > 15 {
		return nil, ErrInvalidAckCount
	}

	// Calculate total size
	size := CalcOverhead(p)

	// Allocate buffer
	buf := make([]byte, size)
	offset := 0

	// Calculate flags
	var flags uint8
	flags = uint8(len(p.Acks)) & FlagAckMask // bits 0-4 for ACK count
	if p.StreamFlagClose {
		flags |= StreamFlagClose
	}
	if p.CloseConnectionFlag {
		flags |= CloseConnectionFlag
	}
	if len(p.Filler) > 0 {
		flags |= FlagFiller
	}
	if p.IsRecipient {
		flags |= FlagRole
	}

	// Flags (8 bits)
	buf[offset] = flags
	offset++

	// Optional ACKs and Window Size
	if len(p.Acks) > 0 {
		// Window Size (32 bits)
		PutUint32(buf[offset:], p.RcvWndSize)
		offset += 4

		// Write ACK SNs (48 bits each)
		for i := 0; i < len(p.Acks); i++ {
			// Write ACK data (StreamId:4, StreamOffset:6, Len:4)
			for i := 0; i < len(p.Acks); i++ {
				PutUint32(buf[offset:], p.Acks[i].StreamId)
				offset += 4
				PutUint48(buf[offset:], p.Acks[i].StreamOffset)
				offset += 6
				PutUint16(buf[offset:], p.Acks[i].Len)
				offset += 2
			}
		}
	}

	if len(p.Filler) > 65535 {
		return nil, ErrFillerTooLarge
	}
	// Optional Filler
	if len(p.Filler) > 0 {
		PutUint16(buf[offset:], uint16(len(p.Filler)))
		offset += 2
		copy(buf[offset:], p.Filler)
		offset += len(p.Filler)
	}

	// Optional Data
	if p.Data != nil {
		PutUint32(buf[offset:], p.Data.StreamId)
		offset += 4
		PutUint48(buf[offset:], p.Data.StreamOffset)
		offset += 6
		copy(buf[offset:], p.Data.Data)
	}

	if offset < 8 {
		return nil, ErrPayloadTooSmall
	}

	return buf, nil
}

func DecodePayload(data []byte) (*Payload, error) {
	if len(data) < MinPayloadSize-PayloadMinSize {
		return nil, ErrPayloadTooSmall
	}

	offset := 0
	payload := &Payload{}

	// Flags (8 bits)
	flags := data[offset]
	offset++

	payload.StreamFlagClose = (flags & StreamFlagClose) != 0
	payload.CloseConnectionFlag = (flags & CloseConnectionFlag) != 0
	fillerFlag := (flags & FlagFiller) != 0
	payload.IsRecipient = (flags & FlagRole) != 0
	ackCount := flags & FlagAckMask

	// Handle ACKs and Window Size if present
	if ackCount > 0 {
		if ackCount > 15 {
			return nil, ErrInvalidAckCount
		}

		// Read Window Size (32 bits)
		payload.RcvWndSize = Uint32(data[offset:])
		offset += 4

		// Read ACK SNs (48 bits each)
		payload.Acks = make([]Ack, ackCount)
		for i := 0; i < int(ackCount); i++ {
			var ack Ack
			ack.StreamId = Uint32(data[offset:])
			offset += 4
			ack.StreamOffset = Uint48(data[offset:])
			offset += 6
			ack.Len = Uint16(data[offset:])
			offset += 2
			payload.Acks[i] = ack
		}
	}

	// Handle Filler if present
	if fillerFlag {
		fillerLen := Uint16(data[offset:])
		offset += 2
		payload.Filler = make([]byte, fillerLen)
		copy(payload.Filler, data[offset:offset+int(fillerLen)])
		offset += int(fillerLen)
	}

	// Handle Data if present
	if offset < len(data) {
		payload.Data = &Data{}
		payload.Data.StreamId = Uint32(data[offset:])
		offset += 4
		payload.Data.StreamOffset = Uint48(data[offset:])
		offset += 6

		// Read remaining bytes as data
		dataLen := len(data) - offset
		payload.Data.Data = make([]byte, dataLen)
		copy(payload.Data.Data, data[offset:])
	}

	return payload, nil
}
