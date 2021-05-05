package ringbufwnd

import (
	"fmt"
	"time"
)

//The send buffer gets the segments in order, but needs to remove them out of order, depending when the
//acks arrive. The send buffer should be able to adapt its size based on the receiver buffer

type Segment interface {
	GetSequenceNumber() uint32
	Timestamp() time.Time
	WasTimedOut() bool
}

type RingBufferSnd struct {
	buffer   []Segment
	capacity uint32
	r        uint32
	w        uint32
	prevSn   uint32
	old      *RingBufferSnd
	newSize  uint32
	//TODO TB: remove the +1 to determine if its full or empty
	n uint32
}

func NewRingBufferSnd(capacity uint32) *RingBufferSnd {
	return &RingBufferSnd{
		buffer:   make([]Segment, capacity+1),
		capacity: capacity + 1,
		prevSn:   uint32(0xffffffff), // -1
	}
}

func (ring *RingBufferSnd) Capacity() uint32 {
	return ring.capacity - 1
}

func (ring *RingBufferSnd) IsEmpty() bool {
	return ring.NumOfSegments() == 0
}

func (ring *RingBufferSnd) NumOfSegments() uint32 {
	num := uint32(0)
	if ring.old != nil {
		num += ring.old.NumOfSegments()
	}
	return num + ring.n
}

func (ring *RingBufferSnd) First() Segment {
	if ring.IsEmpty() {
		return nil
	}
	if ring.old != nil {
		return ring.old.First()
	}
	return ring.buffer[ring.r]
}

func (ring *RingBufferSnd) Resize(targetSize uint32) (bool, *RingBufferSnd) {
	if targetSize == ring.capacity || ring.old != nil {
		return false, ring
	} else {
		r := NewRingBufferSnd(targetSize)
		r.old = ring
		r.prevSn = ring.prevSn
		r.w = (r.prevSn + 1) % r.capacity
		r.r = r.w
		return true, r
	}
}

func (ring *RingBufferSnd) InsertSequence(seg Segment) (bool, error) {
	if ((ring.w + 1) % ring.capacity) == ring.r { //is full
		return false, nil
	}
	if ring.prevSn != seg.GetSequenceNumber()-1 {
		return false, fmt.Errorf("not a sequence, cannot add %v/%v", ring.prevSn, seg.GetSequenceNumber()-1)
	}
	if ring.buffer[ring.w] != nil {
		return false, fmt.Errorf("not empty at pos %v", ring.w)
	}
	ring.prevSn = seg.GetSequenceNumber()
	ring.buffer[ring.w] = seg
	ring.w = (ring.w + 1) % ring.capacity
	ring.n++
	return true, nil
}

func (ring *RingBufferSnd) IsInRetrasmission() bool {
	if ring.old != nil {
		return ring.old.IsInRetrasmission()
	}

	for i := uint32(0); i < ring.capacity; i++ {
		index := (ring.r + i) % ring.capacity
		seg := ring.buffer[index]
		if seg != nil {
			if seg.WasTimedOut(){
				return true
			}
		}

		if ring.w == index {
			break
		}
	}
	return false
}

func (ring *RingBufferSnd) GetTimedout(now time.Time, timeout time.Duration) []Segment {
	var ret []Segment
	if ring.old != nil {
		ret = ring.old.GetTimedout(now, timeout)
	}

	for i := uint32(0); i < ring.capacity; i++ {
		index := (ring.r + i) % ring.capacity
		seg := ring.buffer[index]
		if seg != nil {
			if seg.Timestamp().Add(timeout).Before(now) {
				ret = append(ret, seg)
			}
		}

		if ring.w == index {
			break
		}
	}

	return ret
}

func (ring *RingBufferSnd) Remove(sequenceNumber uint32) (Segment, bool, error) {
	if ring.old != nil {
		seg, empty, err := ring.old.Remove(sequenceNumber)
		if empty {
			ring.old = nil
			empty = false
		}
		if err == nil {
			return seg, empty, nil
		}
	}
	index := sequenceNumber % ring.capacity
	seg := ring.buffer[index]
	if seg == nil {
		return nil, false, fmt.Errorf("already removed %v", index)
	}
	if sequenceNumber != seg.GetSequenceNumber() {
		return nil, false, fmt.Errorf("sn mismatch %v/%v", sequenceNumber, seg.GetSequenceNumber())
	}
	ring.buffer[index] = nil
	ring.n--

	empty := true
	for i := ring.r; i != ring.w; i = (i + 1) % ring.capacity {
		if ring.buffer[i] == nil {
			ring.r = (i + 1) % ring.capacity
		} else {
			empty = false
			break
		}
	}
	return seg, empty, nil
}
