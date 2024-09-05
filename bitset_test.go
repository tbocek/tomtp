package tomtp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNew(t *testing.T) {
	bs := New(0)
	assert.Equal(t, uint64(0), bs.BitSet(), "New() should create an empty BitSet")
}

func TestFrom(t *testing.T) {
	value := uint64(0b1010101010101010)
	bs := New(value)
	assert.Equal(t, value, bs.BitSet(), "From() should create the correct BitSet")
}

func TestSet(t *testing.T) {
	tests := []struct {
		name     string
		initial  uint64
		index    int
		value    uint32
		expected uint64
	}{
		{"Set bit to 1", 0, 3, 1, 0b1000},
		{"Set bit to 0", 0b1111, 2, 0, 0b1011},
		{"Set multiple bits", 0, 0, 0b101, 0b1}, //we cannot set multiple bits
		{"Set bit at max index", 0, 63, 1, 1 << 63},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs := New(tt.initial)
			bs.Set(tt.index, tt.value)
			assert.Equal(t, tt.expected, bs.BitSet(), "Set() result mismatch")
		})
	}
}

func TestBitSet(t *testing.T) {
	value := uint64(0b1010101010101010)
	bs := New(value)
	assert.Equal(t, value, bs.BitSet(), "BitSet() should return the correct value")
}

func TestLen(t *testing.T) {
	bs := New(0)
	assert.Equal(t, maxBits, bs.Len(), "Len() should return maxBits")
}

func TestTest(t *testing.T) {
	tests := []struct {
		name     string
		bitSet   uint64
		index    int
		expected bool
	}{
		{"Test set bit", 0b1000, 3, true},
		{"Test unset bit", 0b1011, 2, false},
		{"Test first bit", 1, 0, true},
		{"Test last bit", 1 << 63, 63, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs := New(tt.bitSet)
			assert.Equal(t, tt.expected, bs.Test(tt.index), "Test() result mismatch")
		})
	}
}

func TestTestInt(t *testing.T) {
	tests := []struct {
		name     string
		bitSet   uint64
		index    int
		expected uint32
	}{
		{"TestInt set bit", 0b1000, 3, 1},
		{"TestInt unset bit", 0b1011, 2, 0},
		{"TestInt first bit", 1, 0, 1},
		{"TestInt last bit", 1 << 63, 63, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs := New(tt.bitSet)
			assert.Equal(t, tt.expected, bs.TestInt(tt.index), "TestInt() result mismatch")
		})
	}
}

func FuzzBitSet(f *testing.F) {
	f.Add(uint64(0), 0, uint32(0))
	f.Add(uint64(0xFFFFFFFFFFFFFFFF), 63, uint32(1))
	f.Add(uint64(0), 32, uint32(0xFFFFFFFF))

	f.Fuzz(func(t *testing.T, initialValue uint64, index int, value uint32) {
		// Ensure index is within bounds
		index = index & 63 // This is equivalent to index % 64, but faster

		bs := New(initialValue)

		// Test Set and Test methods
		bs.Set(index, value)
		expectedSet := value != 0
		if bs.Test(index) != expectedSet {
			t.Errorf("Set(%d, %d) failed: Test(%d) returned %v, expected %v",
				index, value, index, bs.Test(index), expectedSet)
		}

		// Test TestInt method
		expectedTestInt := uint32(0)
		if expectedSet {
			expectedTestInt = 1
		}
		if bs.TestInt(index) != expectedTestInt {
			t.Errorf("TestInt(%d) returned %d, expected %d",
				index, bs.TestInt(index), expectedTestInt)
		}

		// Test BitSet method
		if bs.BitSet() != uint64(*bs) {
			t.Errorf("BitSet() returned %d, expected %d", bs.BitSet(), uint64(*bs))
		}

		// Test Len method
		if bs.Len() != maxBits {
			t.Errorf("Len() returned %d, expected %d", bs.Len(), maxBits)
		}

		// Test multiple Set operations
		for i := 0; i < 10; i++ {
			newIndex := (index + i) & 63
			newValue := uint32(i * 1000000007) // Large prime to get a good distribution of values
			bs.Set(newIndex, newValue)
			expectedNewSet := newValue != 0
			if bs.Test(newIndex) != expectedNewSet {
				t.Errorf("Multiple Set operations failed: Test(%d) returned %v, expected %v",
					newIndex, bs.Test(newIndex), expectedNewSet)
			}
		}
	})
}
