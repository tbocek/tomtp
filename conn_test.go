package tomtp

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

// mockAddr implements net.Addr for testing
type mockAddr struct{}

func (m mockAddr) Network() string { return "mock" }
func (m mockAddr) String() string  { return "mock-address" }

func TestConnection_RTTCalculations(t *testing.T) {
	tests := []struct {
		name         string
		measurements []time.Duration
		alpha        float64
		beta         float64
		wantSRTT     time.Duration
		wantRTO      time.Duration
	}{
		{
			name:         "initial measurement",
			measurements: []time.Duration{100 * time.Millisecond},
			alpha:        0.125,
			beta:         0.25,
			wantSRTT:     100 * time.Millisecond,
			wantRTO:      300 * time.Millisecond, // SRTT + 4*RTTVAR where RTTVAR is SRTT/2
		},
		{
			name:         "multiple measurements",
			measurements: []time.Duration{100 * time.Millisecond, 120 * time.Millisecond, 90 * time.Millisecond},
			alpha:        0.125,
			beta:         0.25,
			wantSRTT:     101 * time.Millisecond, // Approximate due to EMA calculation
			wantRTO:      300 * time.Millisecond, // Should hit minRTO
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &Connection{
				RTT: RTT{
					alpha:  tt.alpha,
					beta:   tt.beta,
					minRTO: 300 * time.Millisecond,
					maxRTO: 60 * time.Second,
				},
			}

			for _, measurement := range tt.measurements {
				conn.UpdateRTT(measurement)
			}

			gotSRTT := conn.GetSRTT()
			gotRTO := conn.GetRTO()

			// Allow for small floating-point differences
			assert.InDelta(t, tt.wantSRTT.Nanoseconds(), gotSRTT.Nanoseconds(), float64(time.Millisecond.Nanoseconds()))
			assert.InDelta(t, tt.wantRTO.Nanoseconds(), gotRTO.Nanoseconds(), float64(time.Millisecond.Nanoseconds()))
		})
	}
}

func TestConnection_GetOrNewStreamRcv(t *testing.T) {
	tests := []struct {
		name     string
		streamID uint32
		setup    bool
	}{
		{
			name:     "new stream",
			streamID: 1,
			setup:    false,
		},
		{
			name:     "existing stream",
			streamID: 2,
			setup:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &Connection{
				streams: make(map[uint32]*Stream),
			}

			stream, isNew := conn.GetOrNewStreamRcv(tt.streamID)
			assert.NotNil(t, stream)
			assert.Equal(t, tt.streamID, stream.streamId)
			assert.Equal(t, !tt.setup, isNew)
		})
	}
}

func TestConnection_Close(t *testing.T) {
	conn := &Connection{
		streams: make(map[uint32]*Stream),
	}

	// Create some test streams
	streamIDs := []uint32{1, 2, 3}
	for _, id := range streamIDs {
		stream, isNew := conn.GetOrNewStreamRcv(id)
		assert.True(t, isNew)
		assert.NotNil(t, stream)
	}

	// Verify streams were created
	assert.Equal(t, len(streamIDs), len(conn.streams))

	// Close connection
	err := conn.Close()
	assert.NoError(t, err)

	// Verify all streams were cleared
	assert.Equal(t, 0, len(conn.streams))
}

func TestConnection_SetAlphaBeta(t *testing.T) {
	conn := &Connection{}

	testCases := []struct {
		name  string
		alpha float64
		beta  float64
	}{
		{
			name:  "standard TCP values",
			alpha: 0.125,
			beta:  0.25,
		},
		{
			name:  "custom values",
			alpha: 0.1,
			beta:  0.2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conn.SetAlphaBeta(tc.alpha, tc.beta)
			assert.Equal(t, tc.alpha, conn.alpha)
			assert.Equal(t, tc.beta, conn.beta)
		})
	}
}

func TestConnection_RTOBounds(t *testing.T) {
	conn := &Connection{
		RTT: RTT{
			alpha:  0.125,
			beta:   0.25,
			minRTO: time.Second,
			maxRTO: 5 * time.Second,
		},
	}

	tests := []struct {
		name        string
		measurement time.Duration
		wantRTO     time.Duration
	}{
		{
			name:        "below minimum RTO",
			measurement: 100 * time.Millisecond,
			wantRTO:     time.Second, // Should be capped at minRTO
		},
		{
			name:        "above maximum RTO",
			measurement: 10 * time.Second,
			wantRTO:     5 * time.Second, // Should be capped at maxRTO
		},
		{
			name:        "within bounds",
			measurement: 100 * time.Millisecond,
			wantRTO:     5 * time.Second, // Should remain unchanged
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn.UpdateRTT(tt.measurement)
			gotRTO := conn.GetRTO()
			assert.Equal(t, tt.wantRTO, gotRTO)
		})
	}
}
