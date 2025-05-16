package tomtp

// Common test struct used across tests
type bbrTestCase struct {
	name               string
	initialState       BBRState
	initialMaxBW       uint64
	initialRttMin      uint64
	initialCwnd        uint64
	initialGrowthCount int
	rttMeasurement     uint64
	bytesAcked         uint64
	timeSinceLastBW    uint64
	mtu                uint64
	expectedState      BBRState
	expectedMaxBW      uint64
	expectedRttMin     uint64
	expectedCwnd       uint64
}
