package tomtp

import (
	"fmt"
	"math/rand"
	"testing"
)

// operation represents a type of map operation to perform
type operationLhm int

const (
	opLhmPut operationLhm = iota
	opLhmGet
	opLhmRemove
	opLhmOldest
	opLhmNext
	opLhmReplace
)

func FuzzLinkedHashMap(f *testing.F) {
	f.Add(int64(1), uint(10))
	f.Add(int64(42), uint(100))
	f.Add(int64(123), uint(500))

	f.Fuzz(func(t *testing.T, seed int64, numOps uint) {
		if numOps > 1000 {
			numOps = 1000
		}

		rng := rand.New(rand.NewSource(seed))
		lhm := newLinkedHashMap[int, string]()
		expected := make(map[int]string)
		insertOrder := make([]int, 0)

		// For debugging
		dumpState := func() string {
			return fmt.Sprintf("Expected: %v\nInsertOrder: %v\nSize: %d",
				expected, insertOrder, lhm.Size())
		}

		validateMap := func(t *testing.T, msg string) {
			t.Helper()

			mapSize := lhm.Size()
			expectedSize := len(expected)
			if expectedSize != mapSize {
				t.Errorf("%s: size mismatch: expected %d, got %d\n%s",
					msg, expectedSize, mapSize, dumpState())
				return
			}

			if expectedSize != len(insertOrder) {
				t.Errorf("%s: insertOrder size mismatch: expected %d, got %d\n%s",
					msg, expectedSize, len(insertOrder), dumpState())
				return
			}

			// Verify forward traversal
			current := lhm.Oldest()
			for i, expectedKey := range insertOrder {
				if current == nil {
					t.Errorf("%s: unexpected nil at position %d\n%s",
						msg, i, dumpState())
					return
				}

				if current.key != expectedKey {
					t.Errorf("%s: key mismatch at position %d: expected %d, got %d\n%s",
						msg, i, expectedKey, current.key, dumpState())
					return
				}

				expectedValue := expected[expectedKey]
				if current.value != expectedValue {
					t.Errorf("%s: value mismatch for key %d: expected %s, got %s\n%s",
						msg, expectedKey, expectedValue, current.value, dumpState())
					return
				}

				current = current.Next()
			}

			if current != nil {
				t.Errorf("%s: unexpected extra elements after traversal\n%s",
					msg, dumpState())
			}

			// Verify all keys are present
			for k, v := range expected {
				if pair := lhm.Get(k); pair == nil {
					t.Errorf("%s: missing key %d\n%s", msg, k, dumpState())
				} else if pair.value != v {
					t.Errorf("%s: incorrect value for key %d: expected %s, got %s\n%s",
						msg, k, v, pair.value, dumpState())
				}
			}
		}

		// Run operations
		for i := uint(0); i < numOps; i++ {
			op := operationLhm(rng.Intn(6))
			switch op {
			case opLhmPut:
				key := rng.Intn(1000)
				value := fmt.Sprintf("value-%d", key)

				oldValue, exists := expected[key]
				if exists && oldValue == value {
					continue // Skip if would be no change
				}

				if lhm.Put(key, value) != nil {
					if !exists {
						insertOrder = append(insertOrder, key)
					}
					expected[key] = value
				}

			case opLhmGet:
				key := rng.Intn(1000)
				result := lhm.Get(key)
				expectedValue, exists := expected[key]

				if exists && result == nil {
					t.Errorf("Get(%d) returned nil for existing key", key)
				} else if !exists && result != nil {
					t.Errorf("Get(%d) returned value for non-existent key", key)
				} else if exists && result.value != expectedValue {
					t.Errorf("Get(%d) returned wrong value: expected %s, got %s",
						key, expectedValue, result.value)
				}

			case opLhmRemove:
				key := rng.Intn(1000)
				_, exists := expected[key]

				result := lhm.Remove(key)
				if exists {
					if result == nil {
						t.Errorf("Remove(%d) returned nil for existing key", key)
					} else {
						delete(expected, key)
						for i, k := range insertOrder {
							if k == key {
								insertOrder = append(insertOrder[:i], insertOrder[i+1:]...)
								break
							}
						}
					}
				} else if result != nil {
					t.Errorf("Remove(%d) returned value for non-existent key", key)
				}

			case opLhmOldest:
				result := lhm.Oldest()
				if len(expected) == 0 {
					if result != nil {
						t.Error("oldest() returned value for empty map")
					}
				} else if result == nil {
					t.Error("oldest() returned nil for non-empty map")
				} else if result.key != insertOrder[0] {
					t.Errorf("oldest() returned wrong key: expected %d, got %d",
						insertOrder[0], result.key)
				}

			case opLhmNext:
				if len(insertOrder) == 0 {
					continue
				}

				idx := rng.Intn(len(insertOrder))
				key := insertOrder[idx]
				current := lhm.Get(key)
				if current == nil {
					t.Errorf("Get(%d) returned nil for existing key", key)
					continue
				}

				next := current.Next()
				isLast := idx == len(insertOrder)-1

				if isLast && next != nil {
					t.Errorf("Next() after last element should be nil, got key %d", next.key)
				} else if !isLast && next == nil {
					t.Errorf("Next() returned nil, expected key %d", insertOrder[idx+1])
				} else if !isLast && next.key != insertOrder[idx+1] {
					t.Errorf("Next() returned wrong key: expected %d, got %d",
						insertOrder[idx+1], next.key)
				}

			case opLhmReplace:
				if len(insertOrder) == 0 {
					continue
				}

				idx := rng.Intn(len(insertOrder))
				oldKey := insertOrder[idx]
				newKey := rng.Intn(1000)
				if oldKey == newKey {
					continue // Skip if same key
				}

				// Skip if new key exists elsewhere in the map
				if _, exists := expected[newKey]; exists {
					continue
				}

				pair := lhm.Get(oldKey)
				if pair == nil {
					t.Errorf("Get(%d) returned nil for existing key", oldKey)
					continue
				}

				newValue := fmt.Sprintf("replaced-%d", newKey)
				pair.Replace(newKey, newValue)

				delete(expected, oldKey)
				expected[newKey] = newValue
				insertOrder[idx] = newKey
			}

			validateMap(t, fmt.Sprintf("After operation %d", i))
		}
	})
}
