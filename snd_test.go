package ringbufwnd

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
	"time"
)

var (
	timeZero = time.Time{}
)

func TestInsert(t *testing.T) {
	r := NewRingBufferSnd(10)
	seg := makeSegment(0)
	_, err := r.InsertSequence(seg)
	assert.NoError(t, err)
}

func TestInsertNotOrdered(t *testing.T) {
	r := NewRingBufferSnd(10)
	seg := makeSegment(0)
	_, err := r.InsertSequence(seg)
	assert.NoError(t, err)
	seg = makeSegment(2)
	_, err = r.InsertSequence(seg)
	assert.Error(t, err)
}

func TestNotOrdered(t *testing.T) {
	r := NewRingBufferSnd(10)
	seg := makeSegment(1)
	_, err := r.InsertSequence(seg)
	assert.Error(t, err)
}

func TestFullSnd(t *testing.T) {
	r := NewRingBufferSnd(10)
	for i := 0; i < 10; i++ {
		seg := makeSegment(uint32(i))
		_, err := r.InsertSequence(seg)
		assert.NoError(t, err)
	}
	seg := makeSegment(11)
	full, _ := r.InsertSequence(seg)
	assert.False(t, full)
}

func TestRemove(t *testing.T) {
	r := NewRingBufferSnd(10)
	for i := 0; i < 10; i++ {
		seg := makeSegment(uint32(i))
		_, err := r.InsertSequence(seg)
		assert.NoError(t, err)
	}
	Segment, _, _  := r.Remove(5)
	fmt.Print("RRRRRRRRRRR: ", Segment,"\n")
	s := r.GetTimedout(timeZero.Add(time.Second+1), time.Second)
	assert.Equal(t, 9, len(s))
}

func TestRemove5(t *testing.T) {
	r := NewRingBufferSnd(10)
	for i := 0; i < 5; i++ {
		seg := makeSegment(uint32(i))
		_, err := r.InsertSequence(seg)
		assert.NoError(t, err)
	}
	r.Remove(4)
	s := r.GetTimedout(timeZero.Add(time.Second+1), time.Second)
	assert.Equal(t, 4, len(s))
}

func TestNoRemove(t *testing.T) {
	r := NewRingBufferSnd(10)
	for i := 0; i < 5; i++ {
		seg := makeSegment(uint32(i))
		_, err := r.InsertSequence(seg)
		assert.NoError(t, err)
	}
	r.Remove(4)
	//no timeout yet
	s := r.GetTimedout(timeZero.Add(time.Second), time.Second)
	assert.Equal(t, 0, len(s))
}

func TestInsertRemove(t *testing.T) {
	r := NewRingBufferSnd(10)

	for i := 0; i < 5; i++ {
		seg := makeSegment(uint32(i))
		_, err := r.InsertSequence(seg)
		assert.NoError(t, err)
	}
	_, _, err := r.Remove(3)
	assert.NoError(t, err)
	_, _, err = r.Remove(1)
	assert.NoError(t, err)

	s := r.GetTimedout(timeZero, time.Second)
	assert.Equal(t, 0, len(s))
	s = r.GetTimedout(timeZero.Add(time.Second+1), time.Second)
	assert.Equal(t, 3, len(s))
}

func TestInsertRemove2(t *testing.T) {
	r := NewRingBufferSnd(10)
	seg := makeSegment(0)
	_, err := r.InsertSequence(seg)
	assert.NoError(t, err)
	_, _, err = r.Remove(0)
	assert.NoError(t, err)
	_, err = r.InsertSequence(seg)
	assert.Error(t, err)
	s := r.GetTimedout(timeZero, time.Second)
	assert.Equal(t, 0, len(s))
	s = r.GetTimedout(timeZero.Add(time.Second+1), time.Second)
	assert.Equal(t, 0, len(s))
}

func TestAlmostFull(t *testing.T) {
	r := NewRingBufferSnd(10)
	for i := 0; i < 10; i++ {
		seg := makeSegment(uint32(i))
		_, err := r.InsertSequence(seg)
		assert.NoError(t, err)
	}
	r.Remove(4)
	seg := makeSegment(10)
	full, err := r.InsertSequence(seg)
	assert.False(t, full)
	r.Remove(0)

	seg = makeSegment(10)
	_, err = r.InsertSequence(seg)
	assert.NoError(t, err)
}

func TestIsEmpty(t *testing.T) {
	r := NewRingBufferSnd(10)
	seg := makeSegment(uint32(0))
	r.InsertSequence(seg)
	assert.False(t, r.IsEmpty())
	r.Remove(0)
	assert.True(t, r.IsEmpty())
}

func TestNumOfSegments(t *testing.T) {
	r := NewRingBufferSnd(10)
	for i := 0; i < 5; i++ {
		seg := makeSegment(uint32(i))
		_, err := r.InsertSequence(seg)
		assert.NoError(t, err)
	}
	assert.Equal(t, uint32(5), r.NumOfSegments())
	r.Remove(2)
	r.Remove(3)
	assert.Equal(t, uint32(3), r.NumOfSegments())
}

func TestFuzz(t *testing.T) {
	r := NewRingBufferSnd(10)

	seqIns := 0
	seqRem := 0
	rand.Seed(42)

	for j := 0; j < 100000; j++ {
		rnd := rand.Intn(10) + 1

		for i := 0; i < rnd; i++ {
			seg := makeSegment(uint32(seqIns))

			ins, err := r.InsertSequence(seg)
			if err != nil {
				assert.NoError(t, err)
			}
			if !ins {
				rnd = i + 1
				break
			} else {
				seqIns++
			}
		}

		rnd2 := rand.Intn(rnd) + 1
		if rand.Intn(2) == 0 {
			rnd2 = rand.Intn(seqIns-seqRem) + 1
		}

		for i := 0; i < rnd2; i++ {
			_, _, err := r.Remove(uint32(seqRem))
			if err != nil {
				assert.NoError(t, err)
				_, _, err = r.Remove(uint32(seqRem))
			}
			seqRem++
		}

		if rand.Intn(3) == 0 {
			_, r = r.Resize(r.capacity + 1)
		}

		//s := r.getTimedout(timeZero.Add(time.Hour))
		//fmt.Printf("size: %v\n", len(s))

	}
	fmt.Printf("send %v, recv %v", seqIns, seqRem)
}
