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

func TestConnection_GetOrNewStreamRcv(t *testing.T) {
	tests := []struct {
		name     string
		streamID uint32
		setup    bool
	}{
		{
			name:     "new stream",
			streamID: 1,
			setup:    true,
		},
		{
			name:     "existing stream",
			streamID: 1,
			setup:    false,
		},
	}
	conn := &Connection{
		streams: make(map[uint32]*Stream),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream, isNew := conn.GetOrNewStreamRcv(tt.streamID)
			assert.NotNil(t, stream)
			assert.Equal(t, tt.streamID, stream.streamId)
			assert.Equal(t, tt.setup, isNew)
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
	conn.Close()

	// Verify all streams were cleared
	assert.Equal(t, 0, len(conn.streams))
}

// TestUpdateRTT tests the RTT calculation logic
func TestUpdateRTT(t *testing.T) {
	tests := []struct {
		name        string
		initialRTT  time.Duration
		initialVar  time.Duration
		measurement time.Duration
		expectedRTT time.Duration
		expectedVar time.Duration
		tolerance   float64 // Tolerance for floating point comparison
	}{
		{
			name:        "First RTT Measurement",
			initialRTT:  0,
			initialVar:  0,
			measurement: 100 * time.Millisecond,
			expectedRTT: 100 * time.Millisecond,
			expectedVar: 50 * time.Millisecond,
			tolerance:   0.001,
		},
		{
			name:        "Increasing RTT",
			initialRTT:  100 * time.Millisecond,
			initialVar:  50 * time.Millisecond,
			measurement: 200 * time.Millisecond,
			expectedRTT: 112500 * time.Microsecond, // 7/8 * 100ms + 1/8 * 200ms
			expectedVar: 62500 * time.Microsecond,  // (50ms*6)/8 + (100ms*2)/8 = 62.5ms
			tolerance:   0.01,
		},
		{
			name:        "Decreasing RTT",
			initialRTT:  200 * time.Millisecond,
			initialVar:  80 * time.Millisecond,
			measurement: 100 * time.Millisecond,
			expectedRTT: 187500 * time.Microsecond, // 7/8 * 200ms + 1/8 * 100ms
			expectedVar: 85000 * time.Microsecond,  // (80ms*6)/8 + (100ms*2)/8 = 85ms
			tolerance:   0.01,
		},
		{
			name:        "Stable RTT",
			initialRTT:  100 * time.Millisecond,
			initialVar:  20 * time.Millisecond,
			measurement: 100 * time.Millisecond,
			expectedRTT: 100 * time.Millisecond,
			expectedVar: 15 * time.Millisecond, // 3/4 * 20ms + 1/4 * 0ms
			tolerance:   0.01,
		},
		{
			name:        "High Variance",
			initialRTT:  100 * time.Millisecond,
			initialVar:  50 * time.Millisecond,
			measurement: 300 * time.Millisecond,
			expectedRTT: 125 * time.Millisecond, // 7/8 * 100ms + 1/8 * 300ms
			expectedVar: 87 * time.Millisecond,  // 3/4 * 50ms + 1/4 * 200ms, rounded to nearest ms
			tolerance:   0.01,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new connection
			conn := &Connection{
				srtt:   tc.initialRTT,
				rttvar: tc.initialVar,
			}

			// Update RTT
			conn.UpdateRTT(tc.measurement)

			// Check if RTT calculation is correct within tolerance
			rttDiff := float64(abs(int64(conn.srtt)-int64(tc.expectedRTT))) / float64(tc.expectedRTT)
			if rttDiff > tc.tolerance {
				t.Errorf("RTT expected %v, got %v, difference %v exceeds tolerance %v",
					tc.expectedRTT, conn.srtt, rttDiff, tc.tolerance)
			}

			// Check if RTT variation calculation is correct within tolerance
			varDiff := float64(abs(int64(conn.rttvar)-int64(tc.expectedVar))) / float64(tc.expectedVar)
			if varDiff > tc.tolerance {
				t.Errorf("RTT variance expected %v, got %v, difference %v exceeds tolerance %v",
					tc.expectedVar, conn.rttvar, varDiff, tc.tolerance)
			}
		})
	}
}

// TestUpdateBBR tests the BBR congestion control logic
func TestUpdateBBR(t *testing.T) {
	type testCase struct {
		name               string
		initialState       BBRState
		initialMaxBW       uint64
		initialRttMin      time.Duration
		initialCwnd        uint64
		initialPacingRate  uint64
		initialGrowthCount int
		rttMeasurement     time.Duration
		bytesAcked         uint64
		timeSinceLastBW    time.Duration
		mtu                int
		expectedState      BBRState
		expectedMaxBW      uint64
		expectedRttMin     time.Duration
		expectedCwnd       uint64
		cwndTolerance      float64 // Tolerance for cwnd comparison
	}

	tests := []testCase{
		{
			name:               "Startup Initial Measurement",
			initialState:       BBRStateStartup,
			initialMaxBW:       0,
			initialRttMin:      time.Hour,
			initialCwnd:        1500, // Using MTU size directly
			initialPacingRate:  12000,
			initialGrowthCount: 0,
			rttMeasurement:     100 * time.Millisecond,
			bytesAcked:         10000,
			timeSinceLastBW:    0,
			mtu:                1500,
			expectedState:      BBRStateStartup,
			expectedMaxBW:      100000, // 10000 bytes / 0.1s = 100,000 bytes/s
			expectedRttMin:     100 * time.Millisecond,
			expectedCwnd:       10 * 1500, // Initial bootstrap
			cwndTolerance:      0.01,
		},
		{
			name:               "Startup Growing Bandwidth",
			initialState:       BBRStateStartup,
			initialMaxBW:       100000,
			initialRttMin:      100 * time.Millisecond,
			initialCwnd:        10 * 1500,
			initialPacingRate:  200000,
			initialGrowthCount: 0,
			rttMeasurement:     100 * time.Millisecond,
			bytesAcked:         20000,
			timeSinceLastBW:    50 * time.Millisecond,
			mtu:                1500,
			expectedState:      BBRStateStartup,
			expectedMaxBW:      200000, // 20000 bytes / 0.1s = 200,000 bytes/s
			expectedRttMin:     100 * time.Millisecond,
			expectedCwnd:       10*1500 + 20000, // Previous + bytesAcked
			cwndTolerance:      0.01,
		},
		{
			name:               "Startup to Normal Transition",
			initialState:       BBRStateStartup,
			initialMaxBW:       200000,
			initialRttMin:      100 * time.Millisecond,
			initialCwnd:        40000,
			initialPacingRate:  400000,
			initialGrowthCount: 2, // Already had 2 non-growing measurements
			rttMeasurement:     100 * time.Millisecond,
			bytesAcked:         15000,
			timeSinceLastBW:    150 * time.Millisecond, // More than 100ms
			mtu:                1500,
			expectedState:      BBRStateNormal, // Should transition to normal
			expectedMaxBW:      200000,         // Not increasing
			expectedRttMin:     100 * time.Millisecond,
			expectedCwnd:       40000 + 15000, // Still increases in startup
			cwndTolerance:      0.01,
		},
		{
			name:               "Normal State with BDP-based cwnd",
			initialState:       BBRStateNormal,
			initialMaxBW:       200000,
			initialRttMin:      100 * time.Millisecond,
			initialCwnd:        55000,
			initialPacingRate:  200000,
			initialGrowthCount: 3,
			rttMeasurement:     120 * time.Millisecond, // Higher RTT, doesn't change min
			bytesAcked:         15000,
			timeSinceLastBW:    200 * time.Millisecond,
			mtu:                1500,
			expectedState:      BBRStateNormal,
			expectedMaxBW:      200000,                 // Not increasing
			expectedRttMin:     100 * time.Millisecond, // Stays at minimum
			expectedCwnd:       40000,                  // BDP-based: 200000 * 0.1s * 1.5 gain
			cwndTolerance:      0.01,
		},
		{
			name:               "Lower RTT Measurement",
			initialState:       BBRStateNormal,
			initialMaxBW:       200000,
			initialRttMin:      100 * time.Millisecond,
			initialCwnd:        30000,
			initialPacingRate:  200000,
			initialGrowthCount: 3,
			rttMeasurement:     80 * time.Millisecond, // Lower RTT
			bytesAcked:         10000,
			timeSinceLastBW:    200 * time.Millisecond,
			mtu:                1500,
			expectedState:      BBRStateNormal,
			expectedMaxBW:      200000,                // Not increasing since bytes/time < maxBW
			expectedRttMin:     80 * time.Millisecond, // Updated to lower value
			expectedCwnd:       32000,                 // BDP-based: 200000 * 0.08s * 1.5 gain
			cwndTolerance:      0.01,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := &Connection{
				mtu: tc.mtu,
				BBR: BBR{
					state:                tc.initialState,
					maxBW:                tc.initialMaxBW,
					rttMin:               tc.initialRttMin,
					cwnd:                 tc.initialCwnd,
					pacingRate:           tc.initialPacingRate,
					bwGrowthCount:        tc.initialGrowthCount,
					cwndGainPct:          200, // Default from NewBBR
					pacingGainPct:        200, // Default from NewBBR
					probeInterval:        1 * time.Second,
					inProbingPhase:       false,
					lastBWUpdateMicros:   time.Now().Add(-tc.timeSinceLastBW).UnixMicro(),
					minRttWindowDuration: 3 * time.Second,
				},
			}

			nowMicros := time.Now().UnixMicro()
			conn.UpdateBBR(tc.rttMeasurement, tc.bytesAcked, nowMicros)

			// Verify state
			if conn.BBR.state != tc.expectedState {
				t.Errorf("Expected BBR state %v, got %v", tc.expectedState, conn.BBR.state)
			}

			// Verify maxBW
			if conn.BBR.maxBW != tc.expectedMaxBW {
				t.Errorf("Expected maxBW %v, got %v", tc.expectedMaxBW, conn.BBR.maxBW)
			}

			// Verify rttMin
			if conn.BBR.rttMin != tc.expectedRttMin {
				t.Errorf("Expected rttMin %v, got %v", tc.expectedRttMin, conn.BBR.rttMin)
			}

			// Verify cwnd with tolerance
			cwndDiff := float64(abs(int64(conn.BBR.cwnd)-int64(tc.expectedCwnd))) / float64(tc.expectedCwnd)
			if cwndDiff > tc.cwndTolerance {
				t.Errorf("Expected cwnd %v, got %v, difference %v exceeds tolerance %v",
					tc.expectedCwnd, conn.BBR.cwnd, cwndDiff, tc.cwndTolerance)
			}
		})
	}
}

// TestBBRProbing tests the probing phase of BBR
func TestBBRProbing(t *testing.T) {
	tests := []struct {
		name                string
		initialProbingState bool
		timeSinceLastProbe  time.Duration
		maxBW               uint64
		expectedInProbe     bool
		expectedPacingGain  int
	}{
		{
			name:                "Start Probing",
			initialProbingState: false,
			timeSinceLastProbe:  1100 * time.Millisecond, // > probe interval
			maxBW:               100000,
			expectedInProbe:     true,
			expectedPacingGain:  150, // Increased for probing
		},
		{
			name:                "During Probing",
			initialProbingState: true,
			timeSinceLastProbe:  100 * time.Millisecond, // < 200ms probe duration
			maxBW:               100000,
			expectedInProbe:     true,
			expectedPacingGain:  150, // Maintained during probe
		},
		{
			name:                "End Probing",
			initialProbingState: true,
			timeSinceLastProbe:  250 * time.Millisecond, // > 200ms probe duration
			maxBW:               100000,
			expectedInProbe:     false,
			expectedPacingGain:  100, // Back to normal
		},
		{
			name:                "No Probing Without BW",
			initialProbingState: false,
			timeSinceLastProbe:  1500 * time.Millisecond, // > probe interval
			maxBW:               0,                       // No bandwidth estimate yet
			expectedInProbe:     false,
			expectedPacingGain:  200, // Unchanged from default
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nowMicros := time.Now().UnixMicro()
			conn := &Connection{
				BBR: BBR{
					state:               BBRStateNormal, // Always in normal state for probing tests
					inProbingPhase:      tc.initialProbingState,
					lastProbeTimeMicros: nowMicros - tc.timeSinceLastProbe.Microseconds(),
					maxBW:               tc.maxBW,
					pacingGainPct:       getPacingGainPct(tc.initialProbingState), // Set based on probing state
					probeInterval:       1 * time.Second,
				},
			}

			conn.handleProbing(nowMicros)

			if conn.BBR.inProbingPhase != tc.expectedInProbe {
				t.Errorf("Expected probing state %v, got %v", tc.expectedInProbe, conn.BBR.inProbingPhase)
			}

			if conn.BBR.pacingGainPct != tc.expectedPacingGain {
				t.Errorf("Expected pacing gain %v, got %v", tc.expectedPacingGain, conn.BBR.pacingGainPct)
			}
		})
	}
}

// TestMinRTTReset tests that minimum RTT is reset after the window duration
func TestMinRTTReset(t *testing.T) {
	tests := []struct {
		name                string
		initialRttMin       time.Duration
		timeSinceLastUpdate time.Duration
		windowDuration      time.Duration
		measurement         time.Duration
		expectedRttReset    bool
	}{
		{
			name:                "Within Window",
			initialRttMin:       100 * time.Millisecond,
			timeSinceLastUpdate: 2 * time.Second,
			windowDuration:      3 * time.Second,
			measurement:         120 * time.Millisecond,
			expectedRttReset:    false, // Should not reset yet
		},
		{
			name:                "Window Expired",
			initialRttMin:       100 * time.Millisecond,
			timeSinceLastUpdate: 4 * time.Second,
			windowDuration:      3 * time.Second,
			measurement:         120 * time.Millisecond,
			expectedRttReset:    true, // Should reset
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nowMicros := time.Now().UnixMicro()
			conn := &Connection{
				BBR: BBR{
					rttMin:               tc.initialRttMin,
					minRttWindowDuration: tc.windowDuration,
					lastBWUpdateMicros:   nowMicros - tc.timeSinceLastUpdate.Microseconds(),
				},
			}

			conn.UpdateBBR(tc.measurement, 1000, nowMicros)

			if tc.expectedRttReset {
				// Should have been reset to a high value first, then set to the measurement
				if conn.BBR.rttMin != tc.measurement {
					t.Errorf("Expected RTT min to be reset to measurement %v, got %v",
						tc.measurement, conn.BBR.rttMin)
				}
			} else {
				// Should still be at initial value
				if conn.BBR.rttMin != tc.initialRttMin {
					t.Errorf("Expected RTT min to remain at %v, got %v",
						tc.initialRttMin, conn.BBR.rttMin)
				}
			}
		})
	}
}

// Helper function for absolute value of int64
func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

// getPacingGain returns the appropriate pacing gain based on probing state
func getPacingGainPct(inProbing bool) int {
	if inProbing {
		return 150
	}
	return 200 // Default from NewBBR
}
