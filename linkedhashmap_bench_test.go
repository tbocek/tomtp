package tomtp

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// BenchmarkLinkedHashMap runs benchmarks for basic operations
func BenchmarkLinkedHashMap(b *testing.B) {
	b.Run("put", func(b *testing.B) {
		lhm := newLinkedHashMap[int, int]()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			lhm.Put(i, i)
		}
	})

	b.Run("get", func(b *testing.B) {
		lhm := newLinkedHashMap[int, int]()
		for i := 0; i < 1000; i++ {
			lhm.Put(i, i)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			lhm.Get(i % 1000)
		}
	})

	b.Run("remove", func(b *testing.B) {
		lhm := newLinkedHashMap[int, int]()
		for i := 0; i < 1000; i++ {
			lhm.Put(i, i)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			lhm.Remove(i % 1000)
		}
	})

	b.Run("oldest", func(b *testing.B) {
		lhm := newLinkedHashMap[int, int]()
		for i := 0; i < 1000; i++ {
			lhm.Put(i, i)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			lhm.Oldest()
		}
	})

	b.Run("next", func(b *testing.B) {
		lhm := newLinkedHashMap[int, int]()
		for i := 0; i < 1000; i++ {
			lhm.Put(i, i)
		}
		first := lhm.Oldest()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			first.Next()
		}
	})

	b.Run("replace", func(b *testing.B) {
		lhm := newLinkedHashMap[int, int]()
		for i := 0; i < 1000; i++ {
			lhm.Put(i, i)
		}
		pair := lhm.Get(500)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			pair.Replace(i+1000, i+1000)
		}
	})
}

// BenchmarkFuzzLinkedHashMap runs benchmarks with random operations
func BenchmarkFuzzLinkedHashMap(b *testing.B) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	b.Run("random_ops", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			iterRng := rand.New(rand.NewSource(rng.Int63()))
			numOps := uint(100)

			lhm := newLinkedHashMap[int, string]()

			// Perform random operations
			for j := uint(0); j < numOps; j++ {
				op := operationLhm(iterRng.Intn(6))
				key := iterRng.Intn(1000)

				switch op {
				case opLhmPut:
					value := fmt.Sprintf("value-%d", key)
					lhm.Put(key, value)
				case opLhmGet:
					lhm.Get(key)
				case opLhmRemove:
					lhm.Remove(key)
				case opLhmOldest:
					lhm.Oldest()
				case opLhmNext:
					if pair := lhm.Get(key); pair != nil {
						pair.Next()
					}
				case opLhmReplace:
					if pair := lhm.Get(key); pair != nil {
						newKey := iterRng.Intn(1000)
						pair.Replace(newKey, fmt.Sprintf("replaced-%d", newKey))
					}
				}
			}
		}
	})

	b.Run("sequential_ops", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			lhm := newLinkedHashMap[int, string]()

			// Sequential insertions
			for j := 0; j < 100; j++ {
				lhm.Put(j, fmt.Sprintf("value-%d", j))
			}

			// Sequential reads
			for j := 0; j < 100; j++ {
				lhm.Get(j)
			}

			// Sequential traversal
			current := lhm.Oldest()
			for current != nil {
				current = current.Next()
			}

			// Sequential removals
			for j := 0; j < 100; j++ {
				lhm.Remove(j)
			}
		}
	})
}
