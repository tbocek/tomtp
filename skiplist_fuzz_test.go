package tomtp

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
)

// operation represents a type of map operation to perform
type operationShm int

const (
	opShmPut operationShm = iota
	opShmGet
	opShmRemove
	opShmMin
	opShmMax
	opShmNext
)

func FuzzSortedHashMap(f *testing.F) {
	// Add some initial seed cases
	f.Add(int64(1), uint(10))    // Small number of operations
	f.Add(int64(42), uint(100))  // Medium number of operations
	f.Add(int64(123), uint(500)) // Large number of operations

	f.Fuzz(func(t *testing.T, seed int64, numOps uint) {
		// Limit the number of operations to prevent too long runs
		if numOps > 1000 {
			numOps = 1000
		}

		// Initialize RNG with the provided seed
		rng := rand.New(rand.NewSource(seed))

		// Create a new map with ascending order
		shm := newSortedHashMap[int, string](func(a, b int, c, d string) bool { return a < b }, func(a, b int, c, d string) bool { return a < b })

		// Keep track of what should be in the map
		expected := make(map[int]string)
		orderedKeys := make([]int, 0)

		// Helper function to keep orderedKeys sorted
		updateOrderedKeys := func() {
			orderedKeys = orderedKeys[:0] // Clear slice while keeping capacity
			for k := range expected {
				orderedKeys = append(orderedKeys, k)
			}
			sort.Ints(orderedKeys)
		}

		// Helper function to validate the map's state
		validateMap := func(t *testing.T, msg string) {
			t.Helper()

			// Verify size
			if len(expected) != shm.Size() {
				t.Errorf("%s: size mismatch: expected %d, got %d",
					msg, len(expected), shm.Size())
				return
			}

			// Verify full traversal matches ordered keys
			if len(expected) > 0 {
				current := shm.Min()
				keyIdx := 0

				for current != nil {
					if keyIdx >= len(orderedKeys) {
						t.Errorf("%s: more elements in tree than expected", msg)
						break
					}

					expectedKey := orderedKeys[keyIdx]
					if current.key != expectedKey {
						t.Errorf("%s: key mismatch at position %d: expected %d, got %d",
							msg, keyIdx, expectedKey, current.key)
					}

					expectedValue := expected[expectedKey]
					if current.value != expectedValue {
						t.Errorf("%s: value mismatch for key %d: expected %s, got %s",
							msg, expectedKey, expectedValue, current.value)
					}

					current = current.Next()
					keyIdx++
				}

				if keyIdx < len(orderedKeys) {
					t.Errorf("%s: fewer elements in tree than expected", msg)
				}
			}
		}

		// Generate and execute random operations
		for i := uint(0); i < numOps; i++ {
			op := operationShm(rng.Intn(6)) // 6 different operations

			switch op {
			case opShmPut:
				key := rng.Intn(1000)
				value := fmt.Sprintf("value-%d", key)
				shm.Put(key, value)
				expected[key] = value
				updateOrderedKeys()

			case opShmGet:
				key := rng.Intn(1000)
				result := shm.Get(key)
				expectedValue, exists := expected[key]

				if exists {
					if result == nil {
						t.Errorf("Get(%d) returned nil, expected value %s",
							key, expectedValue)
					} else if result.value != expectedValue {
						t.Errorf("Get(%d) returned %s, expected %s",
							key, result.value, expectedValue)
					}
				} else if result != nil {
					t.Errorf("Get(%d) returned %v, expected nil", key, result)
				}

			case opShmRemove:
				key := rng.Intn(1000)
				result := shm.Remove(key)
				_, exists := expected[key]

				if exists {
					if result == nil {
						t.Errorf("Remove(%d) returned nil, expected value", key)
					}
					delete(expected, key)
					updateOrderedKeys()
				} else if result != nil {
					t.Errorf("Remove(%d) returned value, expected nil", key)
				}

			case opShmMin:
				result := shm.Min()
				if len(expected) == 0 {
					if result != nil {
						t.Error("Min() returned value for empty map")
					}
				} else {
					if result == nil {
						t.Error("Min() returned nil for non-empty map")
					} else if result.key != orderedKeys[0] {
						t.Errorf("Min() returned %d, expected %d",
							result.key, orderedKeys[0])
					}
				}

			case opShmMax:
				result := shm.Max()
				if len(expected) == 0 {
					if result != nil {
						t.Error("Max() returned value for empty map")
					}
				} else {
					if result == nil {
						t.Error("Max() returned nil for non-empty map")
					} else if result.key != orderedKeys[len(orderedKeys)-1] {
						t.Errorf("Max() returned %d, expected %d",
							result.key, orderedKeys[len(orderedKeys)-1])
					}
				}

			case opShmNext:
				if len(orderedKeys) > 0 {
					// Get a random existing key's index
					idx := rng.Intn(len(orderedKeys))
					key := orderedKeys[idx]
					current := shm.Get(key)

					if current == nil {
						t.Errorf("Get(%d) returned nil for existing key", key)
						continue
					}

					next := current.Next()
					if idx == len(orderedKeys)-1 {
						// Last element should have no next
						if next != nil {
							t.Errorf("Next() after last element returned %v, expected nil",
								next.key)
						}
					} else {
						// Should have next element
						expectedNext := orderedKeys[idx+1]
						if next == nil {
							t.Errorf("Next() returned nil, expected %d", expectedNext)
						} else if next.key != expectedNext {
							t.Errorf("Next() returned %d, expected %d",
								next.key, expectedNext)
						}
					}
				}
			}

			// Validate map state after each operation
			validateMap(t, fmt.Sprintf("After operation %d", i))
		}
	})
}
