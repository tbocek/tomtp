package ringbufwnd

//The receiving buffer gets segments that can be out of order. That means, the insert needs
//to store the segments out of order. The remove of segments affect those segments
//that are in order

type RingBufferRcv struct {
	buffer    []Segment
	capacity  uint32
	nextRead  uint32
	minGoodSn uint32
	old       []Segment
	size      uint32
	notify    func()
}

// NewRingBufferRcv creates a new receiving buffer, the capacity can be changed later.
func NewRingBufferRcv(capacity uint32) *RingBufferRcv {
	return &RingBufferRcv{
		buffer:   make([]Segment, capacity),
		capacity: capacity,
	}
}

func NewRingBufferRcvNotify(capacity uint32, notify func()) *RingBufferRcv {
	return &RingBufferRcv{
		buffer:   make([]Segment, capacity),
		capacity: capacity,
		notify:   notify,
	}
}

// Capacity The current total capacity of the receiving buffer. This is the total size.
func (ring *RingBufferRcv) Capacity() uint32 {
	return ring.capacity
}

// Size The current size of the receiving buffer. Capacity - Size, gives you the amount
// of available space
func (ring *RingBufferRcv) Size() uint32 {
	return ring.size
}

func (ring *RingBufferRcv) Insert(seg Segment) bool {
	sn := seg.getSequenceNumber()

	maxSn := ring.minGoodSn + ring.capacity
	//overflow situation
	if maxSn < ring.minGoodSn {
		if sn > maxSn && sn < ring.minGoodSn {
			return false
		}
	} else {
		//no overflow
		if sn > maxSn {
			//the receiving buffer is too small cannot add data beyond the size of the buffer
			return false
		}
	}

	minSn := ring.minGoodSn - ring.capacity
	//underflow situation
	if ring.minGoodSn <= ring.capacity {
		if sn < minSn && sn < ring.minGoodSn {
			return false
		}
	} else {
		//no underflow
		if sn < minSn {
			//the receiving buffer is too small cannot add data beyond the size of the buffer
			return false
		}
	}

	index := sn % ring.capacity
	if ring.buffer[index] != nil {
		//we may receive a duplicate, don't add
		return false
	}
	ring.buffer[index] = seg
	ring.size++
	if index == ring.nextRead && ring.notify != nil {
		ring.notify()
	}
	return true
}

func (ring *RingBufferRcv) Remove() Segment {
	//fast path
	seg := ring.buffer[ring.nextRead]
	if seg == nil {
		return nil
	}

	ring.buffer[ring.nextRead] = nil
	ring.nextRead = (ring.nextRead + 1) % ring.capacity
	ring.minGoodSn = seg.getSequenceNumber()
	ring.drainOverflow()
	ring.size--
	return seg
}

func (ring *RingBufferRcv) drainOverflow() {
	if ring.old != nil && len(ring.old) > 0 {
		inserted := ring.Insert(ring.old[0])
		if inserted {
			ring.old = ring.old[1:]
			ring.size--
		}
	} else {
		ring.old = nil
	}
}

//size of RTO could be measured by RTT and bandwidth
//https://www.sciencedirect.com/topics/computer-science/maximum-window-size

func (ring *RingBufferRcv) Resize(capacity uint32) *RingBufferRcv {
	if capacity == ring.capacity {
		return ring
	}

	rNew := NewRingBufferRcv(capacity)
	rNew.minGoodSn = ring.minGoodSn
	rNew.nextRead = (rNew.minGoodSn + 1) % rNew.capacity
	rNew.old = ring.buffer

	j := 0
	for i := uint32(0); i < ring.capacity; i++ {
		if ring.buffer[i] == nil {
			continue
		}
		inserted := rNew.Insert(ring.buffer[i])
		if !inserted {
			rNew.old[j] = ring.buffer[i]
			j++
		}
	}
	rNew.old = rNew.old[:j]
	return rNew
}
