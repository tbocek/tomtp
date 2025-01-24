package tomtp

import (
	"github.com/stretchr/testify/suite"
	"testing"
)

type SortedHashMapTestSuite struct {
	suite.Suite
	shm *SortedHashMap[int, string]
}

func (s *SortedHashMapTestSuite) SetupTest() {
	s.shm = NewSortedHashMap[int, string](func(a, b int) bool { return a < b })
}

func TestSortedHashMapSuite(t *testing.T) {
	suite.Run(t, new(SortedHashMapTestSuite))
}

func (s *SortedHashMapTestSuite) TestNewMap() {
	s.NotNil(s.shm)
	s.Equal(0, s.shm.Size())
}

func (s *SortedHashMapTestSuite) TestPutAndGet() {
	// Test basic put and get
	s.True(s.shm.Put(1, "one"))
	pair := s.shm.Get(1)
	s.NotNil(pair)
	s.Equal(1, pair.Key)
	s.Equal("one", pair.Value)

	// Test updating existing key
	s.True(s.shm.Put(1, "ONE"))
	pair = s.shm.Get(1)
	s.Equal("ONE", pair.Value)

	// Test nil value with pointer type
	shm := NewSortedHashMap[int, *string](func(a, b int) bool { return a < b })
	var nilStr *string
	s.False(shm.Put(2, nilStr))

	// Test non-existent key
	s.Nil(s.shm.Get(999))
}

func (s *SortedHashMapTestSuite) TestSize() {
	s.Equal(0, s.shm.Size())

	s.shm.Put(1, "one")
	s.Equal(1, s.shm.Size())

	s.shm.Put(2, "two")
	s.Equal(2, s.shm.Size())

	s.shm.Remove(1)
	s.Equal(1, s.shm.Size())
}

func (s *SortedHashMapTestSuite) TestRemove() {
	// Test removing non-existent key
	s.Nil(s.shm.Remove(1))

	// Add some items
	s.shm.Put(1, "one")
	s.shm.Put(2, "two")
	s.shm.Put(3, "three")

	// Test removing leaf node
	pair := s.shm.Remove(3)
	s.NotNil(pair)
	s.Equal(3, pair.Key)
	s.Equal("three", pair.Value)
	s.Nil(s.shm.Get(3))

	// Test removing node with one child
	s.shm.Put(4, "four")
	pair = s.shm.Remove(2)
	s.NotNil(pair)
	s.Equal(2, pair.Key)
	s.Equal(2, s.shm.Size())

	// Test removing root
	pair = s.shm.Remove(1)
	s.NotNil(pair)
	s.Equal(1, pair.Key)
	s.Equal(1, s.shm.Size())
}

func (s *SortedHashMapTestSuite) TestMinMax() {
	// Test empty map
	s.Nil(s.shm.Min())
	s.Nil(s.shm.Max())

	// Add items in non-sorted order
	s.shm.Put(5, "five")
	s.shm.Put(3, "three")
	s.shm.Put(7, "seven")
	s.shm.Put(1, "one")
	s.shm.Put(9, "nine")

	// Test min
	min := s.shm.Min()
	s.NotNil(min)
	s.Equal(1, min.Key)
	s.Equal("one", min.Value)

	// Test max
	max := s.shm.Max()
	s.NotNil(max)
	s.Equal(9, max.Key)
	s.Equal("nine", max.Value)

	// Remove min and max
	s.shm.Remove(1)
	s.shm.Remove(9)

	// Check new min/max
	min = s.shm.Min()
	s.Equal(3, min.Key)
	max = s.shm.Max()
	s.Equal(7, max.Key)
}

func (s *SortedHashMapTestSuite) TestNext() {
	// Test empty map
	s.Nil(s.shm.Min())

	// Add items
	values := map[int]string{
		5: "five",
		3: "three",
		7: "seven",
		1: "one",
		9: "nine",
		4: "four",
		6: "six",
	}
	for k, v := range values {
		s.shm.Put(k, v)
	}

	// Test in-order traversal
	expected := []int{1, 3, 4, 5, 6, 7, 9}
	current := s.shm.Min()
	for i, exp := range expected {
		s.NotNil(current)
		s.Equal(exp, current.Key)
		s.Equal(values[exp], current.Value)
		current = current.Next()
		if i == len(expected)-1 {
			s.Nil(current) // No next after last element
		}
	}
}

func (s *SortedHashMapTestSuite) TestConcurrentAccess() {
	done := make(chan bool)
	go func() {
		for i := 0; i < 100; i++ {
			s.shm.Put(i, "value")
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			s.shm.Get(i)
		}
		done <- true
	}()

	<-done
	<-done
}

func (s *SortedHashMapTestSuite) TestCustomComparator() {
	// Test with reverse order comparator
	reverseMap := NewSortedHashMap[int, string](func(a, b int) bool { return a > b })

	values := []int{5, 3, 7, 1, 9}
	for _, v := range values {
		reverseMap.Put(v, "value")
	}

	// Check reverse order
	current := reverseMap.Min()
	expected := []int{9, 7, 5, 3, 1}
	for _, exp := range expected {
		s.NotNil(current)
		s.Equal(exp, current.Key)
		current = current.Next()
	}
}

func (s *SortedHashMapTestSuite) TestComplexTree() {
	// Build a complex tree with multiple levels and test various removal scenarios
	values := []int{8, 4, 12, 2, 6, 10, 14, 1, 3, 5, 7, 9, 11, 13, 15}
	for _, v := range values {
		s.shm.Put(v, "value")
	}

	// Test removing nodes with two children
	pair := s.shm.Remove(8) // root
	s.NotNil(pair)
	s.Equal(8, pair.Key)

	// Verify tree structure remains valid
	current := s.shm.Min()
	expected := []int{1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15}
	for _, exp := range expected {
		s.NotNil(current)
		s.Equal(exp, current.Key)
		current = current.Next()
	}

	// Remove more nodes with two children
	s.shm.Remove(4)
	s.shm.Remove(12)

	// Verify again
	current = s.shm.Min()
	expected = []int{1, 2, 3, 5, 6, 7, 9, 10, 11, 13, 14, 15}
	for _, exp := range expected {
		s.NotNil(current)
		s.Equal(exp, current.Key)
		current = current.Next()
	}
}
