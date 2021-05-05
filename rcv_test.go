package ringbufwnd

import (
	"container/list"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"sync"
	"testing"
	"time"
)

type seg struct {
	seq uint32
}

func (s seg) GetSequenceNumber() uint32 {
	return s.seq
}
func (s seg) Timestamp() time.Time {
	return timeZero
}

func (s seg) WasTimedOut() bool{
	return false
}

func makeSegment(data uint32) Segment {
	return seg{data}
}

func TestInsertOutOfOrder(t *testing.T) {
	r := NewRingBufferRcv(10)
	seg := makeSegment(1)
	inserted := r.Insert(seg)
	assert.True(t, inserted)

	s := r.Remove()
	assert.Equal(t, nil, s)
}


func TestParallel(t *testing.T){
	r := NewRingBufferRcv(100)

	mutex := sync.WaitGroup{}
	mutex.Add(4)


	go func() {
		for i := uint32(0); i <= uint32(9); i++ {
			if i < uint32(5) {
				seg := makeSegment(i)
				r.Insert(seg)
			}
		}
		mutex.Done()
	}()
	go func() {
		for i := uint32(10); i <= uint32(19); i++ {
			seg := makeSegment(i)
			r.Insert(seg)
		}
		mutex.Done()
	}()
	go func() {
		for i := uint32(0); i <= uint32(9); i++ {
			if i >= uint32(5) {
				seg := makeSegment(i)
				r.Insert(seg)
			}
		}
		mutex.Done()
		}()

	go func() {
		//var i uint32 = r.Size()
		var l list.List
		 i := r.Size()
		for {
			if u := r.Size(); i != u{
				//fmt.Print(r.size)
				i = u
			}
			if r.Size() == 20{
				break
			}


		}
		fmt.Print("listsize", l.Len() ,"\n")
		mutex.Done()
	}()
	mutex.Wait()


	for{
		seg := r.Remove()
		if seg == nil {
			break
		}
		fmt.Print(seg)
	}


}

func TestInsertOutOfOrder2(t *testing.T) {
	r := NewRingBufferRcv(10)
	seg := makeSegment(1)
	inserted := r.Insert(seg)
	assert.True(t, inserted)

	seg = makeSegment(0)
	inserted = r.Insert(seg)
	assert.True(t, inserted)

	s1 := r.Remove()
	s2 := r.Remove()
	s3 := r.Remove()
	assert.True(t, s1 != nil)
	assert.True(t, s2 != nil)
	assert.True(t, s3 == nil)
}

func TestInsertBackwards(t *testing.T) {
	r := NewRingBufferRcv(10)
	for i := 0; i < 9; i++ {
		seg := makeSegment(uint32(9 - i))
		inserted := r.Insert(seg)
		assert.True(t, inserted)
	}
	s := r.Remove()
	assert.Equal(t, nil, s)

	seg := makeSegment(0)
	inserted := r.Insert(seg)
	assert.True(t, inserted)

	i := removeUntilNil(r)
	assert.Equal(t, 10, i)

}

func TestInsertTwice(t *testing.T) {
	r := NewRingBufferRcv(10)
	seg := makeSegment(1)
	inserted := r.Insert(seg)
	assert.True(t, inserted)
	seg = makeSegment(1)
	inserted = r.Insert(seg)
	assert.False(t, inserted)
}

func TestFull(t *testing.T) {
	r := NewRingBufferRcv(10)

	for i := 0; i < 10; i++ {
		seg := makeSegment(uint32(i))
		inserted := r.Insert(seg)
		assert.True(t, inserted)
	}

	seg := makeSegment(uint32(11))
	inserted := r.Insert(seg)
	assert.False(t, inserted)
}

func TestModulo(t *testing.T) {
	r := NewRingBufferRcv(10)

	for i := 0; i < 10; i++ {
		seg := makeSegment(uint32(i))
		inserted := r.Insert(seg)
		assert.True(t, inserted)
	}

	i := removeUntilNil(r)
	assert.Equal(t, 10, i)

	for i := 10; i < 20; i++ {
		seg := makeSegment(uint32(i))
		inserted := r.Insert(seg)
		assert.True(t, inserted)
	}

	i = removeUntilNil(r)
	assert.Equal(t, 10, i)
}

func TestWrongSN(t *testing.T) {
	r := NewRingBufferRcv(10)
	seg := makeSegment(1)
	inserted := r.Insert(seg)
	assert.True(t, inserted)
	seg = makeSegment(2)
	inserted = r.Insert(seg)
	inserted = r.Insert(seg)
	assert.False(t, inserted)
}

func TestFuzz2(t *testing.T) {
	r := NewRingBufferRcv(10)

	seqIns := 0
	seqRem := 0
	rand.Seed(42)

	for j := 0; j < 10000; j++ {
		rnd := rand.Intn(int(r.Capacity())) + 1

		j := 0
		for i := rnd - 1; i >= 0; i-- {
			seg := makeSegment(uint32(seqIns + i))
			inserted := r.Insert(seg)
			if inserted {
				j++
			}
		}
		seqIns += j

		seqRem += removeUntilNil(r)

		if rand.Intn(3) == 0 {
			r = r.Resize(r.Size() + 1)
		}
	}
	assert.Equal(t, 10013, seqIns)
	assert.Equal(t, 10013, seqRem)
}

func removeUntilNil(r *RingBufferRcv) int {
	seg := r.Remove()
	i := 0
	for seg != nil {
		seg = r.Remove()
		i++
	}
	return i
}
