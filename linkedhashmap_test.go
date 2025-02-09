package tomtp

import (
	"fmt"
	"github.com/stretchr/testify/suite"
	"sync"
	"testing"
)

type LinkedHashMapTestSuite struct {
	suite.Suite
	lhm *linkedHashMap[string, int]
}

func (s *LinkedHashMapTestSuite) SetupTest() {
	s.lhm = newLinkedHashMap[string, int]()
}

func TestLinkedHashMapSuite(t *testing.T) {
	suite.Run(t, new(LinkedHashMapTestSuite))
}

func (s *LinkedHashMapTestSuite) TestBasicOperations() {
	// Test empty map
	s.Equal(0, s.lhm.Size())
	s.Nil(s.lhm.Oldest())
	s.Nil(s.lhm.Get("nonexistent"))

	// Test single item operations
	s.True(s.lhm.Put("one", 1))
	s.Equal(1, s.lhm.Size())

	result := s.lhm.Get("one")
	s.NotNil(result)
	s.Equal(1, result.value)

	// Test update
	s.True(s.lhm.Put("one", 100))
	result = s.lhm.Get("one")
	s.Equal(100, result.value)
	s.Equal(1, s.lhm.Size())
}

func (s *LinkedHashMapTestSuite) TestRemoveOperations() {
	// Test Remove on empty map
	s.Nil(s.lhm.Remove("nonexistent"))

	// Setup test data
	s.lhm.Put("first", 1)
	s.lhm.Put("second", 2)
	s.lhm.Put("third", 3)

	// Test removing middle element
	result := s.lhm.Remove("second")
	s.NotNil(result)
	s.Equal(2, result.value)
	s.Equal(2, s.lhm.Size())

	// Verify links are maintained
	s.Equal("third", s.lhm.head.nxt.key)
	s.Equal("first", s.lhm.tail.prev.key)

	// Test removing nonexistent after some exist
	s.Nil(s.lhm.Remove("nonexistent"))

	// Remove remaining elements
	s.NotNil(s.lhm.Remove("first"))
	s.NotNil(s.lhm.Remove("third"))
	s.Equal(0, s.lhm.Size())
	s.Nil(s.lhm.head)
	s.Nil(s.lhm.tail)
}

func (s *LinkedHashMapTestSuite) TestInsertionOrder() {
	items := []struct {
		key string
		val int
	}{
		{"one", 1},
		{"two", 2},
		{"three", 3},
		{"four", 4},
	}

	// Insert items
	for _, item := range items {
		s.lhm.Put(item.key, item.val)
	}

	// Verify order through iteration
	current := s.lhm.head
	for i, expected := range items {
		s.Require().NotNil(current, "Unexpected nil at position %d", i)
		s.Equal(expected.key, current.key)
		s.Equal(expected.val, current.value)
		current = current.nxt
	}
	s.Nil(current, "Expected nil after last element")

	// Verify reverse order
	current = s.lhm.tail
	for i := len(items) - 1; i >= 0; i-- {
		s.Require().NotNil(current, "Unexpected nil at position %d", i)
		s.Equal(items[i].key, current.key)
		s.Equal(items[i].val, current.value)
		current = current.prev
	}
	s.Nil(current, "Expected nil before first element")
}

func (s *LinkedHashMapTestSuite) TestNextOperation() {
	// Test Next on nil pair
	var nilPair *lhmPair[string, int]
	s.Nil(nilPair.Next())

	// Test Next with empty map
	pair := &lhmPair[string, int]{m: s.lhm}
	s.Nil(pair.Next())

	// Test Next with items
	s.lhm.Put("first", 1)
	s.lhm.Put("second", 2)
	s.lhm.Put("third", 3)

	first := s.lhm.Get("first")
	second := first.Next()
	third := second.Next()

	s.Equal("second", second.key)
	s.Equal("third", third.key)
	s.Nil(third.Next())
}

func (s *LinkedHashMapTestSuite) TestConcurrentOperations() {
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
				s.lhm.Put(fmt.Sprintf("key%d", val), val)
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
					s.lhm.Get(fmt.Sprintf("key%d", j))
				} else {
					s.lhm.Remove(fmt.Sprintf("key%d", j))
				}
			}
		}()
	}

	wg.Wait()
}

func (s *LinkedHashMapTestSuite) TestReplaceOperations() {
	// Test basic replacement
	s.lhm.Put("old", 1)
	pair := s.lhm.Get("old")
	pair.Replace("new", 100)

	result := s.lhm.Get("new")
	s.NotNil(result)
	s.Equal(100, result.value)
	s.Nil(s.lhm.Get("old"))
	s.Equal(1, s.lhm.Size())
}

func (s *LinkedHashMapTestSuite) TestEdgeCases() {
	// Test single item removal
	s.lhm.Put("single", 1)
	s.lhm.Remove("single")
	s.Nil(s.lhm.head)
	s.Nil(s.lhm.tail)

	// Test head/tail operations
	s.lhm.Put("first", 1)
	s.lhm.Put("second", 2)
	s.lhm.Put("third", 3)

	s.lhm.Remove("third") // Remove tail
	s.Equal("second", s.lhm.tail.key)
	s.Nil(s.lhm.tail.nxt)

	s.lhm.Remove("first") // Remove head
	s.Equal("second", s.lhm.head.key)
	s.Nil(s.lhm.head.prev)
}

func (s *LinkedHashMapTestSuite) TestTypeSpecificBehavior() {
	// Test string representation
	pair := &lhmPair[string, int]{value: 42}
	s.Equal("{value: 42}", pair.String())

	pairUint := &lhmPair[string, uint64]{value: uint64(1234567890)}
	s.Equal("{Time: 1234567890}", pairUint.String())

	// Test nil/zero value handling
	lhmPtr := newLinkedHashMap[string, *int]()
	s.False(lhmPtr.Put("key", nil))
	s.Equal(0, lhmPtr.Size())

	lhmInterface := newLinkedHashMap[string, interface{}]()
	s.False(lhmInterface.Put("key", nil))
	s.Equal(0, lhmInterface.Size())
}
