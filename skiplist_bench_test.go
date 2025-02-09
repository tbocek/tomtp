package tomtp

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// BenchmarkSortedHashMap runs benchmarks for basic operations
func BenchmarkSortedHashMap(b *testing.B) {
	b.Run("put", func(b *testing.B) {
		shm := newSortedHashMap[int, int](func(a, b int) bool { return a < b })
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			shm.Put(i, i)
		}
	})

	b.Run("get", func(b *testing.B) {
		shm := newSortedHashMap[int, int](func(a, b int) bool { return a < b })
		for i := 0; i < 1000; i++ {
			shm.Put(i, i)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			shm.Get(i % 1000)
		}
	})

	b.Run("remove", func(b *testing.B) {
		shm := newSortedHashMap[int, int](func(a, b int) bool { return a < b })
		for i := 0; i < 1000; i++ {
			shm.Put(i, i)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			shm.Remove(i % 1000)
		}
	})
}

// BenchmarkFuzzSortedHashMap runs benchmarks with random operations
func BenchmarkFuzzSortedHashMap(b *testing.B) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < b.N; i++ {
		seed := rng.Int63()
		// Create a new RNG for each iteration to ensure deterministic behavior
		iterRng := rand.New(rand.NewSource(seed))
		numOps := uint(100)

		shm := newSortedHashMap[int, string](func(a, b int) bool { return a < b })
		expected := make(map[int]string)

		// Perform random operations
		for j := uint(0); j < numOps; j++ {
			op := operationShm(iterRng.Intn(6))
			key := iterRng.Intn(1000)

			switch op {
			case opShmPut:
				value := fmt.Sprintf("value-%d", key)
				shm.Put(key, value)
				expected[key] = value
			case opShmGet:
				shm.Get(key)
			case opShmRemove:
				shm.Remove(key)
				delete(expected, key)
			case opShmMin:
				shm.Min()
			case opShmMax:
				shm.Max()
			case opShmNext:
				if pair := shm.Get(key); pair != nil {
					pair.Next()
				}
			}
		}
	}
}
