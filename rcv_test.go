package tomtp

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestReceiveBuffer_BasicOperations(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Test initial state
	if rb.Size() != 0 {
		t.Errorf("Initial size = %v, want 0", rb.Size())
	}
	if rb.IsClosed() {
		t.Error("New buffer should not be closed")
	}

	// Test basic insert and remove
	segment := &RcvSegment{
		offset: 0,
		data:   []byte("hello"),
	}

	if status := rb.Insert(segment); status != RcvInsertOk {
		t.Errorf("Insert status = %v, want %v", status, RcvInsertOk)
	}

	if got := rb.Size(); got != 5 {
		t.Errorf("After insert size = %v, want 5", got)
	}

	// Test removal
	if got := rb.RemoveOldestInOrder(); got == nil {
		t.Error("RemoveOldestInOrder() = nil, want segment")
	} else if !bytes.Equal(got.data, []byte("hello")) {
		t.Errorf("RemoveOldestInOrder() data = %v, want %v", got.data, []byte("hello"))
	}
}

func TestReceiveBuffer_OutOfOrderInsert(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert out of order segments
	segments := []*RcvSegment{
		{offset: 5, data: []byte("world")},
		{offset: 0, data: []byte("hello")},
	}

	// Insert out of order
	for _, seg := range segments {
		if status := rb.Insert(seg); status != RcvInsertOk {
			t.Errorf("Insert status = %v, want %v", status, RcvInsertOk)
		}
	}

	// Should only get the first segment
	if got := rb.RemoveOldestInOrder(); got == nil {
		t.Error("RemoveOldestInOrder() = nil, want first segment")
	} else if !bytes.Equal(got.data, []byte("hello")) {
		t.Errorf("RemoveOldestInOrder() data = %v, want %v", got.data, []byte("hello"))
	}

	// Second segment should now be available
	if got := rb.RemoveOldestInOrder(); got == nil {
		t.Error("RemoveOldestInOrder() = nil, want second segment")
	} else if !bytes.Equal(got.data, []byte("world")) {
		t.Errorf("RemoveOldestInOrder() data = %v, want %v", got.data, []byte("world"))
	}
}

func TestReceiveBuffer_Duplicates(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Test exact duplicate
	seg1 := &RcvSegment{offset: 0, data: []byte("hello")}
	if status := rb.Insert(seg1); status != RcvInsertOk {
		t.Errorf("First insert status = %v, want %v", status, RcvInsertOk)
	}

	if status := rb.Insert(seg1); status != RcvInsertDuplicate {
		t.Errorf("Duplicate insert status = %v, want %v", status, RcvInsertDuplicate)
	}

	// Test larger retransmission
	seg2 := &RcvSegment{offset: 0, data: []byte("hello_world")}
	if status := rb.Insert(seg2); status != RcvInsertOk {
		t.Errorf("Larger segment insert status = %v, want %v", status, RcvInsertOk)
	}

	// Test smaller retransmission
	seg3 := &RcvSegment{offset: 0, data: []byte("hi")}
	if status := rb.Insert(seg3); status != RcvInsertDuplicate {
		t.Errorf("Smaller segment insert status = %v, want %v", status, RcvInsertDuplicate)
	}
}

func TestReceiveBuffer_PartialData(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert and remove first segment
	seg1 := &RcvSegment{offset: 0, data: []byte("hello")}
	rb.Insert(seg1)
	rb.RemoveOldestInOrder()

	// Try to insert segment that overlaps with removed data
	seg2 := &RcvSegment{offset: 3, data: []byte("lo_world")}
	if status := rb.Insert(seg2); status != RcvInsertOk {
		t.Errorf("Partial new data insert status = %v, want %v", status, RcvInsertOk)
	}

	// Check that only new data was stored
	if got := rb.RemoveOldestInOrder(); got == nil {
		t.Error("RemoveOldestInOrder() = nil, want partial segment")
	} else if !bytes.Equal(got.data, []byte("_world")) {
		t.Errorf("Partial segment data = %v, want %v", got.data, []byte("_world"))
	}
}

func TestReceiveBuffer_Capacity(t *testing.T) {
	rb := NewReceiveBuffer(10) // Small capacity

	// Fill buffer
	seg1 := &RcvSegment{offset: 0, data: bytes.Repeat([]byte("a"), 8)}
	if status := rb.Insert(seg1); status != RcvInsertOk {
		t.Errorf("First insert status = %v, want %v", status, RcvInsertOk)
	}

	// Try to exceed capacity
	seg2 := &RcvSegment{offset: 8, data: bytes.Repeat([]byte("b"), 4)}
	if status := rb.Insert(seg2); status != RcvInsertBufferFull {
		t.Errorf("Exceeding capacity status = %v, want %v", status, RcvInsertBufferFull)
	}

	// Remove some data and try again
	rb.RemoveOldestInOrder()
	if status := rb.Insert(seg2); status != RcvInsertOk {
		t.Errorf("After removal insert status = %v, want %v", status, RcvInsertOk)
	}
}

func TestReceiveBuffer_Close(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert before closing
	seg1 := &RcvSegment{offset: 0, data: []byte("hello")}
	if status := rb.Insert(seg1); status != RcvInsertOk {
		t.Errorf("Pre-close insert status = %v, want %v", status, RcvInsertOk)
	}

	// Close buffer
	rb.Close()
	if !rb.IsClosed() {
		t.Error("IsClosed() = false after Close()")
	}

	// Try to insert after closing
	seg2 := &RcvSegment{offset: 5, data: []byte("world")}
	if status := rb.Insert(seg2); status != RcvInsertBufferFull {
		t.Errorf("Post-close insert status = %v, want %v", status, RcvInsertBufferFull)
	}

	// Should still be able to remove
	if got := rb.RemoveOldestInOrder(); got == nil {
		t.Error("RemoveOldestInOrder() = nil after close")
	}
}

func TestReceiveBuffer_NonByteTypes(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Test with string type
	seg1 := &RcvSegment{offset: 0, data: []byte("hello")}
	if status := rb.Insert(seg1); status != RcvInsertOk {
		t.Errorf("String insert status = %v, want %v", status, RcvInsertOk)
	}

	if got := rb.RemoveOldestInOrder(); got == nil {
		assert.Equal(t, got.data, []byte("hello"))
		t.Error("Failed to handle string type correctly")
	}

	// Test with custom type
	type CustomType struct{ value int }
	rb2 := NewReceiveBuffer(1000)

	seg2 := &RcvSegment{offset: 0, data: []byte{42}}
	if status := rb2.Insert(seg2); status != RcvInsertOk {
		t.Errorf("Custom type insert status = %v, want %v", status, RcvInsertOk)
	}
}

func TestReceiveBuffer_OverlappingRanges(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert first segment
	seg1 := &RcvSegment{
		offset: 100,
		data:   []byte("middle"),
	}
	rb.Insert(seg1)

	// Test cases for overlapping segments
	tests := []struct {
		name       string
		segment    *RcvSegment
		wantSize   int
		wantStatus RcvInsertStatus
	}{
		{
			name: "before existing range",
			segment: &RcvSegment{
				offset: 90,
				data:   []byte("beforemid"),
			},
			wantSize:   14,
			wantStatus: RcvInsertOk,
		},
		{
			name: "after existing range",
			segment: &RcvSegment{
				offset: 106,
				data:   []byte("endpart"),
			},
			wantSize:   21,
			wantStatus: RcvInsertOk,
		},
		{
			name: "completely within range",
			segment: &RcvSegment{
				offset: 101,
				data:   []byte("mid"),
			},
			wantSize:   21,
			wantStatus: RcvInsertDuplicate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := rb.Insert(tt.segment)
			if status != tt.wantStatus {
				t.Errorf("Insert status = %v, want %v", status, tt.wantStatus)
			}
			if got := rb.Size(); got != tt.wantSize {
				t.Errorf("Size after insert = %v, want %v", got, tt.wantSize)
			}
		})
	}
}

func TestReceiveBuffer_SequentialRemoval(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert segments out of order
	segments := []*RcvSegment{
		{offset: 10, data: []byte("third")},
		{offset: 0, data: []byte("first")},
		{offset: 5, data: []byte("second")},
	}

	for _, seg := range segments {
		rb.Insert(seg)
	}

	// Remove segments in order
	expected := [][]byte{
		[]byte("first"),
		[]byte("second"),
		[]byte("third"),
	}

	for i, want := range expected {
		got := rb.RemoveOldestInOrder()
		if got == nil {
			t.Fatalf("RemoveOldestInOrder() returned nil for segment %d", i)
		}
		if !bytes.Equal(got.data, want) {
			t.Errorf("Segment %d data = %v, want %v", i, got.data, want)
		}
	}

	// Verify buffer is empty
	if rb.Size() != 0 {
		t.Errorf("Final size = %v, want 0", rb.Size())
	}
}

func TestReceiveBuffer_48BitRollover(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Set nextOffset near the 48-bit limit
	rb.nextOffset = MaxUint48 - 10

	tests := []struct {
		name        string
		insert      *RcvSegment
		wantStatus  RcvInsertStatus
		wantRemove  bool   // whether RemoveOldestInOrder should return a segment
		checkOffset bool   // whether to check the nextOffset after removal
		wantOffset  uint64 // expected nextOffset after removal
	}{
		{
			name: "insert at rollover boundary",
			insert: &RcvSegment{
				offset: MaxUint48 - 10,
				data:   []byte("rollover"),
			},
			wantStatus:  RcvInsertOk,
			wantRemove:  true,
			checkOffset: true,
			wantOffset:  MaxUint48 - 2, // -10 + 8 (len("rollover"))
		},
		{
			name: "insert spanning rollover",
			insert: &RcvSegment{
				offset: MaxUint48 - 2,
				data:   []byte("span"),
			},
			wantStatus:  RcvInsertOk,
			wantRemove:  true,
			checkOffset: true,
			wantOffset:  2, // (MaxUint48 - 2 + 4) % MaxUint48
		},
		{
			name: "insert after rollover",
			insert: &RcvSegment{
				offset: 2,
				data:   []byte("after"),
			},
			wantStatus:  RcvInsertOk,
			wantRemove:  true,
			checkOffset: true,
			wantOffset:  7, // 2 + 5
		},
		{
			name: "duplicate after rollover",
			insert: &RcvSegment{
				offset: 2,
				data:   []byte("duplicate"),
			},
			wantStatus:  RcvInsertDuplicate,
			wantRemove:  false,
			checkOffset: false,
		},
		{
			name: "old data before rollover",
			insert: &RcvSegment{
				offset: MaxUint48 - 20,
				data:   []byte("old"),
			},
			wantStatus:  RcvInsertDuplicate,
			wantRemove:  false,
			checkOffset: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Insert segment
			status := rb.Insert(tt.insert)
			if status != tt.wantStatus {
				t.Errorf("Insert() status = %v, want %v", status, tt.wantStatus)
			}

			// Check removal if expected
			if tt.wantRemove {
				got := rb.RemoveOldestInOrder()
				if got == nil {
					t.Fatal("RemoveOldestInOrder() = nil, want segment")
				}
				if !bytes.Equal(got.data, tt.insert.data) {
					t.Errorf("RemoveOldestInOrder() data = %v, want %v", got.data, tt.insert.data)
				}
				if tt.checkOffset && rb.nextOffset != tt.wantOffset {
					t.Errorf("nextOffset after remove = %v, want %v", rb.nextOffset, tt.wantOffset)
				}
			}
		})
	}
}

func TestReceiveBuffer_LargeSequenceJump(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Test large sequence number jumps
	segments := []*RcvSegment{
		{offset: 5, data: []byte("first")},
		{offset: MaxUint48 - 10, data: []byte("jump")},
		{offset: 2, data: []byte("after_rollover")},
	}

	// Insert all segments (out of order)
	for _, seg := range segments {
		status := rb.Insert(seg)
		if status != RcvInsertOk {
			t.Errorf("Insert offset %v status = %v, want %v", seg.offset, status, RcvInsertOk)
		}
	}

	// Only the first segment should be available for removal
	got := rb.RemoveOldestInOrder()
	if got == nil || got.offset != 5 {
		t.Errorf("RemoveOldestInOrder() offset = %v, want 5", got.offset)
	}
}

func TestReceiveBuffer_ExactRollover(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	rb.nextOffset = MaxUint48 - 1

	// Test exact rollover point
	seg1 := &RcvSegment{
		offset: MaxUint48 - 1,
		data:   []byte("x"),
	}
	if status := rb.Insert(seg1); status != RcvInsertOk {
		t.Errorf("Insert at MaxUint48-1 status = %v, want %v", status, RcvInsertOk)
	}

	got := rb.RemoveOldestInOrder()
	if got == nil {
		t.Fatal("RemoveOldestInOrder() = nil, want segment")
	}

	// Next offset should be exactly 0
	if rb.nextOffset != 0 {
		t.Errorf("nextOffset = %v, want 0", rb.nextOffset)
	}

	// Insert at offset 0 should work
	seg2 := &RcvSegment{
		offset: 0,
		data:   []byte("y"),
	}
	if status := rb.Insert(seg2); status != RcvInsertOk {
		t.Errorf("Insert at 0 status = %v, want %v", status, RcvInsertOk)
	}
}
