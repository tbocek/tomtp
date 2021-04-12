package ringbufwnd

import (
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
	"time"
)

type seg struct {
	seq uint32
}

func (s seg) getSequenceNumber() uint32 {
	return s.seq
}
func (s seg) timestamp() time.Time {
	return timeZero
}

func makeSegment(data uint32) segment {
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

func removeUntilNil(r *ringBufferRcv) int {
	seg := r.Remove()
	i := 0
	for seg != nil {
		seg = r.Remove()
		i++
	}
	return i
}
