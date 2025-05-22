package tomtp

import (
	"github.com/stretchr/testify/assert"
	"testing"
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
		streams: newStreamHashMap(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := conn.Stream(tt.streamID)
			assert.NotNil(t, stream)
			assert.Equal(t, tt.streamID, stream.streamId)
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
