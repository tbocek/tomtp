package tomtp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

type Payload struct {
	StreamId   uint32
	LastGoodSn *uint32
	SackRanges []SackRange
	RcwWndSize uint32
	Close      bool
	Sn         *uint32
	Data       []byte
}

type SackRange struct {
	from uint32
	to   uint32
}

func EncodePayload(
	streamId uint32,
	lastGoodSn *uint32,
	sackRanges []SackRange,
	rcvWndSize uint32,
	close bool,
	sn uint32,
	data []byte,
	w io.Writer) (n int, err error) {

	//write streamId
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, streamId); err != nil {
		return 0, err
	}

	if err := binary.Write(buf, binary.BigEndian, rcvWndSize); err != nil {
		return 0, err
	}

	var ackHeader byte = byte(0)
	if len(data) > 0 {
		ackHeader |= byte(1 << 7) // Set DATA bit if we have data
	}
	if close {
		ackHeader |= byte(1 << 6) // Set FIN bit if close is true
	}
	if lastGoodSn != nil {
		ackHeader |= byte(1 << 5) // ACK/SACK bit set if they are present
	}

	if len(sackRanges) > 0 {
		if len(sackRanges) > 8 {
			return 0, errors.New("S/ACK length more than 8")
		}
		ackHeader |= byte((len(sackRanges) << 2) & 0x1C)
	}

	err = buf.WriteByte(ackHeader)
	if err != nil {
		return 0, err
	}

	//sequence number acks data
	if lastGoodSn != nil {
		if err := binary.Write(buf, binary.BigEndian, *lastGoodSn); err != nil {
			return 0, err
		}
		if len(sackRanges) > 0 {
			for _, val := range sackRanges {
				if err := binary.Write(buf, binary.BigEndian, val.from); err != nil {
					return 0, err
				}
				if err := binary.Write(buf, binary.BigEndian, val.to); err != nil {
					return 0, err
				}
			}
		}
	}

	if len(data) > 0 {
		if err := binary.Write(buf, binary.BigEndian, sn); err != nil {
			return 0, err
		}

		//write data
		_, err = buf.Write(data)
		if err != nil {
			return 0, err
		}
	}

	return w.Write(buf.Bytes())
}

func DecodePayload(buf *bytes.Buffer, n int) (payload *Payload, err error) {

	payload = &Payload{}
	if err := binary.Read(buf, binary.BigEndian, &payload.StreamId); err != nil {
		return nil, err
	}

	if err := binary.Read(buf, binary.BigEndian, &payload.RcwWndSize); err != nil {
		return nil, err
	}

	var ackHeader uint8
	if err := binary.Read(buf, binary.BigEndian, &ackHeader); err != nil {
		return nil, err
	}

	var dataBit bool
	if ackHeader&(1<<7) != 0 {
		dataBit = true
	}

	// check FIN bit
	if ackHeader&(1<<6) != 0 {
		payload.Close = true
	}

	// check ACK/SACK bit
	if ackHeader&(1<<5) != 0 {
		payload.LastGoodSn = new(uint32)
		if err := binary.Read(buf, binary.BigEndian, payload.LastGoodSn); err != nil {
			return nil, err
		}
	}

	// check SACK length
	sackLen := int(ackHeader&0x1C) >> 2
	if sackLen > 0 {
		payload.SackRanges = make([]SackRange, sackLen)
		for i := 0; i < sackLen; i++ {
			if err := binary.Read(buf, binary.BigEndian, &payload.SackRanges[i].from); err != nil {
				return nil, err
			}
			if err := binary.Read(buf, binary.BigEndian, &payload.SackRanges[i].to); err != nil {
				return nil, err
			}
		}
	}

	if dataBit {
		sn := uint32(0)
		if err := binary.Read(buf, binary.BigEndian, &sn); err != nil {
			return nil, err
		}
		payload.Sn = &sn
		// The rest of the buffer is considered the payload data
		payload.Data = buf.Bytes()
	}

	return payload, nil
}
