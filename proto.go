package tomtp

import (
	"errors"
)

const (
	PayloadMinSize = 5

	StreamFlagAckMask = 0x1F // bits 0-4 for ACK count (0-31)
	StreamFlagClose   = 1 << 5
	StreamFlagFiller  = 1 << 6
	StreamFlagRole    = 1 << 7
)

var (
	ErrPayloadTooSmall = errors.New("payload size below minimum of 8 bytes")
	ErrFillerTooLarge  = errors.New("filler length has limit of 65536")
	ErrInvalidAckCount = errors.New("invalid ACK count")
)

type Payload struct {
	StreamId    uint32
	CloseFlag   bool
	AckCount    uint8 // 0-15
	IsRecipient bool
	RcvWndSize  uint32   // Only present when AckCount > 0
	AckSns      []uint64 // Length matches AckCount, each 48 bits
	StreamSn    uint64   // Only present with Data, 48 bits
	Data        []byte
	Filler      []byte
}

func EncodePayload(p *Payload) ([]byte, error) {
	if p.AckCount > 15 {
		return nil, ErrInvalidAckCount
	}

	// Calculate total size
	size := PayloadMinSize
	if p.AckCount > 0 {
		size += 4                   // RcvWndSize
		size += int(p.AckCount) * 6 // ACK SNs (48 bits each)
	}
	if len(p.Filler) > 0 {
		size += 2             // FillerLength
		size += len(p.Filler) // Filler data
	}
	if len(p.Data) > 0 {
		size += 6           // StreamSn
		size += len(p.Data) // Data
	}

	// Allocate buffer
	buf := make([]byte, size)
	offset := 0

	// Calculate flags
	var flags uint8
	flags = p.AckCount & StreamFlagAckMask // bits 0-4 for ACK count
	if p.CloseFlag {
		flags |= StreamFlagClose
	}
	if len(p.Filler) > 0 {
		flags |= StreamFlagFiller
	}
	if p.IsRecipient {
		flags |= StreamFlagRole
	}

	// Flags (8 bits)
	buf[offset] = flags
	offset++

	// StreamId (32 bits)
	PutUint32(buf[offset:], p.StreamId)
	offset += 4

	// Optional ACKs and Window Size
	if p.AckCount > 0 {
		// Window Size (32 bits)
		PutUint32(buf[offset:], p.RcvWndSize)
		offset += 4

		// Write ACK SNs (48 bits each)
		for i := 0; i < int(p.AckCount); i++ {
			PutUint48(buf[offset:], p.AckSns[i])
			offset += 6
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
	if len(p.Data) > 0 {
		// Write StreamSn (48 bits)
		PutUint48(buf[offset:], p.StreamSn)
		offset += 6

		copy(buf[offset:], p.Data)
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

	payload.CloseFlag = (flags & StreamFlagClose) != 0
	fillerFlag := (flags & StreamFlagFiller) != 0
	payload.IsRecipient = (flags & StreamFlagRole) != 0
	payload.AckCount = flags & StreamFlagAckMask

	// StreamId (32 bits)
	payload.StreamId = Uint32(data[offset:])
	offset += 4

	// Handle ACKs and Window Size if present
	if payload.AckCount > 0 {
		if payload.AckCount > 15 {
			return nil, ErrInvalidAckCount
		}

		// Read Window Size (32 bits)
		payload.RcvWndSize = Uint32(data[offset:])
		offset += 4

		// Read ACK SNs (48 bits each)
		payload.AckSns = make([]uint64, payload.AckCount)
		for i := 0; i < int(payload.AckCount); i++ {
			payload.AckSns[i] = Uint48(data[offset:])
			offset += 6
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
		// Read StreamSn (48 bits)
		payload.StreamSn = Uint48(data[offset:])
		offset += 6

		// Read remaining bytes as data
		dataLen := len(data) - offset
		payload.Data = make([]byte, dataLen)
		copy(payload.Data, data[offset:])
	}

	return payload, nil
}
