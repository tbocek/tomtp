package tomtp

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestReceiveBuffer(t *testing.T) {
	tests := []struct {
		name             string
		segments         []*RcvSegment
		capacity         int
		want             []*RcvSegment
		wantInsertStatus []RcvInsertStatus
	}{
		{
			name:     "Single segment",
			capacity: 1000,
			segments: []*RcvSegment{
				{offset: 0, data: []byte("data")},
			},
			want: []*RcvSegment{
				{offset: 0, data: []byte("data")},
			},
			wantInsertStatus: []RcvInsertStatus{RcvInsertOk},
		},
		{
			name:     "Duplicate exact segment",
			capacity: 1000,
			segments: []*RcvSegment{
				{offset: 0, data: []byte("data")},
				{offset: 0, data: []byte("data")},
			},
			want: []*RcvSegment{
				{offset: 0, data: []byte("data")},
			},
			wantInsertStatus: []RcvInsertStatus{RcvInsertOk, RcvInsertDuplicate},
		},
		{
			name:     "Gap between segments",
			capacity: 1000,
			segments: []*RcvSegment{
				{offset: 10, data: []byte("later")},
				{offset: 0, data: []byte("early")},
			},
			want: []*RcvSegment{
				{offset: 0, data: []byte("early")},
			},
			wantInsertStatus: []RcvInsertStatus{RcvInsertOk, RcvInsertOk},
		},
		{
			name:     "Buffer full exact",
			capacity: 4,
			segments: []*RcvSegment{
				{offset: 0, data: []byte("data")},
				{offset: 4, data: []byte("more")},
			},
			want: []*RcvSegment{
				{offset: 0, data: []byte("data")},
			},
			wantInsertStatus: []RcvInsertStatus{RcvInsertOk, RcvInsertBufferFull},
		},
		{
			name:     "Zero length segment",
			capacity: 1000,
			segments: []*RcvSegment{
				{offset: 0, data: []byte{}},
			},
			want: []*RcvSegment{
				{offset: 0, data: []byte{}},
			},
			wantInsertStatus: []RcvInsertStatus{RcvInsertOk},
		},
		{
			name:     "Consecutive segments different arrival order",
			capacity: 1000,
			segments: []*RcvSegment{
				{offset: 5, data: []byte("second")},
				{offset: 0, data: []byte("first")},
				{offset: 11, data: []byte("third")},
			},
			want: []*RcvSegment{
				{offset: 0, data: []byte("first")},
				{offset: 5, data: []byte("second")},
				{offset: 11, data: []byte("third")},
			},
			wantInsertStatus: []RcvInsertStatus{RcvInsertOk, RcvInsertOk, RcvInsertOk},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rb := NewReceiveBuffer(tt.capacity)

			for i, seg := range tt.segments {
				status := rb.Insert(seg)
				assert.Equal(t, tt.wantInsertStatus[i], status)
			}

			var got []*RcvSegment
			for {
				seg := rb.RemoveOldestInOrder()
				if seg == nil {
					break
				}
				got = append(got, seg)
			}

			assert.Equal(t, len(tt.want), len(got))
			for i := range got {
				require.Less(t, i, len(tt.want))
				assert.Equal(t, tt.want[i].offset, got[i].offset)
				assert.Equal(t, tt.want[i].data, got[i].data)
			}
		})
	}
}

func TestGetAcks(t *testing.T) {
	tests := []struct {
		name     string
		inserts  int
		wantLens []int
	}{
		{
			name:     "No acks",
			inserts:  0,
			wantLens: []int{0},
		},
		{
			name:     "Single batch under limit",
			inserts:  10,
			wantLens: []int{10, 0},
		},
		{
			name:     "Multiple batches",
			inserts:  35,
			wantLens: []int{15, 15, 5, 0},
		},
		{
			name:     "Exact batch Size",
			inserts:  15,
			wantLens: []int{15, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rb := NewReceiveBuffer(1000)

			for i := 0; i < tt.inserts; i++ {
				rb.Insert(&RcvSegment{
					offset: uint64(i * 10),
					data:   []byte("data"),
				})
			}

			for _, wantLen := range tt.wantLens {
				acks := rb.GetAcks()
				if wantLen == 0 {
					assert.Nil(t, acks)
				} else {
					assert.Equal(t, wantLen, len(acks))
				}
			}
		})
	}
}
