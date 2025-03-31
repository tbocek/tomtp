package tomtp

import (
	"github.com/stretchr/testify/suite"
	"sync"
	"testing"
)

type SortedHashMapTestSuite struct {
	suite.Suite
	shm *skipList[int, string]
}

func (s *SortedHashMapTestSuite) SetupTest() {
	s.shm = newSortedHashMap[int, string](func(a, b int, c, d string) bool { return a < b }, func(a, b int, c, d string) bool { return a < b })
}

func TestSortedHashMapSuite(t *testing.T) {
	suite.Run(t, new(SortedHashMapTestSuite))
}

func (s *SortedHashMapTestSuite) TestBasicOperations() {
	// Test empty map
	s.NotNil(s.shm)
	s.Equal(0, s.shm.Size())
	s.Nil(s.shm.Min())
	s.Nil(s.shm.Max())

	// Test basic Put and Get
	s.True(s.shm.Put(1, "one"))
	pair := s.shm.Get(1)
	s.NotNil(pair)
	s.Equal(1, pair.key)
	s.Equal("one", pair.value)

	// Test updating existing key
	s.True(s.shm.Put(1, "ONE"))
	pair = s.shm.Get(1)
	s.Equal("ONE", pair.value)
	s.Equal(1, s.shm.Size())

	// Test non-existent key
	s.Nil(s.shm.Get(999))
}

func (s *SortedHashMapTestSuite) TestNilValueHandling() {
	// Test nil value with pointer type
	shmPtr := newSortedHashMap[int, *string](func(a, b int, c, d *string) bool { return a < b }, func(a, b int, c, d *string) bool { return a < b })
	var nilStr *string
	s.False(shmPtr.Put(2, nilStr))
	s.Equal(0, shmPtr.Size())

	// Test with interface map
	shmInterface := newSortedHashMap[int, interface{}](func(a, b int, c, d interface{}) bool { return a < b }, func(a, b int, c, d interface{}) bool { return a < b })
	s.False(shmInterface.Put(1, nil))
	s.Equal(0, shmInterface.Size())
}

func (s *SortedHashMapTestSuite) TestTreeOperations() {
	values := []struct {
		key   int
		value string
	}{
		{5, "five"},
		{3, "three"},
		{7, "seven"},
		{1, "one"},
		{9, "nine"},
		{4, "four"},
		{6, "six"},
	}

	// InsertBlocking values
	for _, v := range values {
		s.shm.Put(v.key, v.value)
	}

	// Test ordered traversal
	expected := []int{1, 3, 4, 5, 6, 7, 9}
	current := s.shm.Min()
	for i, exp := range expected {
		s.Require().NotNil(current, "Unexpected nil at position %d", i)
		s.Equal(exp, current.key)
		current = current.Next()
	}
	s.Nil(current, "Expected nil after last element")
}

func (s *SortedHashMapTestSuite) TestRemoveOperations() {
	// Test removing from empty map
	s.Nil(s.shm.Remove(1))

	// Build a complex tree
	values := []int{8, 4, 12, 2, 6, 10, 14, 1, 3, 5, 7, 9, 11, 13, 15}
	for _, v := range values {
		s.shm.Put(v, "value")
	}

	// Test removing leaf node
	pair := s.shm.Remove(15)
	s.NotNil(pair)
	s.Equal(15, pair.key)
	s.Nil(s.shm.Get(15))

	// Test removing node with one child
	pair = s.shm.Remove(14)
	s.NotNil(pair)
	s.Equal(14, pair.key)
	s.Equal(13, s.shm.Max().key)

	// Test removing node with two children
	pair = s.shm.Remove(8)
	s.NotNil(pair)
	s.Equal(8, pair.key)

	// Verify tree structure remains valid
	current := s.shm.Min()
	expected := []int{1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13}
	for _, exp := range expected {
		s.NotNil(current)
		s.Equal(exp, current.key)
		current = current.Next()
	}
}

func (s *SortedHashMapTestSuite) TestMinMaxOperations() {
	// Test empty map
	s.Nil(s.shm.Min())
	s.Nil(s.shm.Max())

	// Add items in non-sorted order
	values := map[int]string{
		5: "five",
		3: "three",
		7: "seven",
		1: "one",
		9: "nine",
	}
	for k, v := range values {
		s.shm.Put(k, v)
	}

	// Test extremes
	s.Equal(1, s.shm.Min().key)
	s.Equal("one", s.shm.Min().value)
	s.Equal(9, s.shm.Max().key)
	s.Equal("nine", s.shm.Max().value)

	// Test after removing extremes
	s.shm.Remove(1)
	s.shm.Remove(9)
	s.Equal(3, s.shm.Min().key)
	s.Equal(7, s.shm.Max().key)
}

func (s *SortedHashMapTestSuite) TestNextOperations() {
	// Test Next on empty map
	s.Nil(s.shm.Min())

	// Test Next with single element
	s.shm.Put(1, "one")
	first := s.shm.Min()
	s.NotNil(first)
	s.Nil(first.Next())

	// Test Next with multiple elements
	s.shm.Put(2, "two")
	s.shm.Put(3, "three")

	current := s.shm.Min()
	s.Equal(1, current.key)
	current = current.Next()
	s.Equal(2, current.key)
	current = current.Next()
	s.Equal(3, current.key)
	s.Nil(current.Next())
}

func (s *SortedHashMapTestSuite) TestConcurrentOperations() {
	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				val := base*numOperations + j
				s.shm.Put(val, "value")
			}
		}(i)
	}

	// Concurrent reads and removes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				if j%2 == 0 {
					s.shm.Get(j)
				} else {
					s.shm.Remove(j)
				}
			}
		}()
	}

	wg.Wait()
}

func (s *SortedHashMapTestSuite) TestCustomComparators() {
	// Test with reverse order comparator
	reverseMap := newSortedHashMap[int, string](func(a, b int, c, d string) bool { return a > b }, func(a, b int, c, d string) bool { return a > b })
	values := []int{5, 3, 7, 1, 9}
	for _, v := range values {
		reverseMap.Put(v, "value")
	}

	// Verify reverse order
	current := reverseMap.Min()
	expected := []int{9, 7, 5, 3, 1}
	for _, exp := range expected {
		s.NotNil(current)
		s.Equal(exp, current.key)
		current = current.Next()
	}

	// Test with custom struct keys
	type CustomKey struct {
		value int
	}
	customMap := newSortedHashMap[CustomKey, string](
		func(a, b CustomKey, c, d string) bool { return a.value < b.value },
		func(a, b CustomKey, c, d string) bool { return a.value < b.value },
	)
	customMap.Put(CustomKey{1}, "one")
	customMap.Put(CustomKey{2}, "two")
	s.Equal("one", customMap.Min().value)
}
