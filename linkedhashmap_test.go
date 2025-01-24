package tomtp

import (
	"github.com/stretchr/testify/suite"
	"sync"
	"testing"
)

type LinkedHashMapTestSuite struct {
	suite.Suite
	lhm *LinkedHashMap[string, int]
}

func (s *LinkedHashMapTestSuite) SetupTest() {
	s.lhm = NewLinkedHashMap[string, int]()
}

func TestLinkedHashMapSuite(t *testing.T) {
	suite.Run(t, new(LinkedHashMapTestSuite))
}

func (s *LinkedHashMapTestSuite) TestPutAndGet() {
	// Test putting and getting values
	s.True(s.lhm.Put("one", 1))
	result := s.lhm.Get("one")
	s.Equal(1, result.Value)

	// Test getting non-existent value
	result = s.lhm.Get("doesnotexist")
	s.Nil(result) // zero value for int

	// Test updating existing value
	s.True(s.lhm.Put("one", 100))
	result = s.lhm.Get("one")
	s.Equal(100, result.Value)
}

func (s *LinkedHashMapTestSuite) TestSizeAndClear() {
	s.Equal(0, s.lhm.Size())
	s.lhm.Put("one", 1)
	s.lhm.Put("two", 2)
	s.Equal(2, s.lhm.Size())
}

func (s *LinkedHashMapTestSuite) TestRemove() {
	s.lhm.Put("one", 1)
	s.lhm.Put("two", 2)

	// Test removing existing item
	result := s.lhm.Remove("one")
	s.Equal(1, result.Value)
	result = s.lhm.Get("one")
	s.Nil(result) // zero value for int
	s.Equal(1, s.lhm.Size())

	// Test removing non-existent item
	result = s.lhm.Remove("doesnotexist")
	s.Nil(result) // zero value for int
}

func (s *LinkedHashMapTestSuite) TestInsertionOrder() {
	values := []int{1, 2, 3, 4}
	expectedOrder := []string{"one", "two", "three", "four"}

	for i, key := range expectedOrder {
		s.lhm.Put(key, values[i])
	}

	current := s.lhm.head
	for i := 0; current != nil; i++ {
		s.Equal(expectedOrder[i], current.Key)
		s.Equal(values[i], current.Value)
		current = current.next
	}
}

func (s *LinkedHashMapTestSuite) TestOldestAndNewest() {
	// Test empty map
	pair := s.lhm.Oldest()
	s.Nil(pair)
	pair = s.lhm.Newest()
	s.Nil(pair)

	// Add items
	s.lhm.Put("first", 1)
	s.lhm.Put("second", 2)
	s.lhm.Put("third", 3)

	// Check oldest
	pair = s.lhm.Oldest()
	s.Equal("first", pair.Key)
	s.Equal(1, pair.Value)

	// Check newest
	pair = s.lhm.Newest()
	s.Equal("third", pair.Key)
	s.Equal(3, pair.Value)

	// Remove oldest and check new oldest
	s.lhm.Remove("first")
	pair = s.lhm.Oldest()
	s.Equal("second", pair.Key)
	s.Equal(2, pair.Value)
}

func (s *LinkedHashMapTestSuite) TestConcurrency() {
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
				s.lhm.Put("key", val)
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				s.lhm.Get("key")
			}
		}()
	}

	wg.Wait()
}

// Benchmark tests
func BenchmarkLinkedHashMap(b *testing.B) {
	b.Run("Put", func(b *testing.B) {
		lhm := NewLinkedHashMap[int, int]()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			lhm.Put(i, i)
		}
	})

	b.Run("Get", func(b *testing.B) {
		lhm := NewLinkedHashMap[int, int]()
		for i := 0; i < 1000; i++ {
			lhm.Put(i, i)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			lhm.Get(i % 1000)
		}
	})
}

func TestFrontEmpty(t *testing.T) {
	m := NewLinkedHashMap[string, int]()
	if pair := m.Front(); pair != nil {
		t.Errorf("Expected nil for empty map, got %v", pair)
	}
}

func TestFrontSingle(t *testing.T) {
	m := NewLinkedHashMap[string, int]()
	m.Put("a", 1)

	pair := m.Front()
	if pair == nil {
		t.Fatal("Expected non-nil pair")
	}
	if pair.Key != "a" || pair.Value != 1 {
		t.Errorf("Expected {a,1}, got {%v,%v}", pair.Key, pair.Value)
	}
}

func TestFrontMultiple(t *testing.T) {
	m := NewLinkedHashMap[string, int]()
	m.Put("a", 1)
	m.Put("b", 2)

	pair := m.Front()
	if pair == nil {
		t.Fatal("Expected non-nil pair")
	}
	if pair.Key != "a" || pair.Value != 1 {
		t.Errorf("Expected {a,1}, got {%v,%v}", pair.Key, pair.Value)
	}
}

func TestNextNil(t *testing.T) {
	var pair *LhmPair[string, int]
	if next := pair.Next(); next != nil {
		t.Errorf("Expected nil for nil pair, got %v", next)
	}
}

func TestNextEmpty(t *testing.T) {
	m := NewLinkedHashMap[string, int]()
	pair := &LhmPair[string, int]{m: m}
	if next := pair.Next(); next != nil {
		t.Errorf("Expected nil for empty map, got %v", next)
	}
}

func TestNextSequence(t *testing.T) {
	m := NewLinkedHashMap[string, int]()
	m.Put("a", 1)
	m.Put("b", 2)
	m.Put("c", 3)

	expected := []struct {
		key string
		val int
	}{
		{"a", 1},
		{"b", 2},
		{"c", 3},
	}

	pair := m.Front()
	for i, exp := range expected {
		if pair == nil {
			t.Fatalf("Step %d: Unexpected nil pair", i)
		}
		if pair.Key != exp.key || pair.Value != exp.val {
			t.Errorf("Step %d: Expected {%v,%v}, got {%v,%v}",
				i, exp.key, exp.val, pair.Key, pair.Value)
		}
		pair = pair.Next()
	}

	if pair != nil {
		t.Error("Expected nil after last element")
	}
}

func TestNextAfterRemoval(t *testing.T) {
	m := NewLinkedHashMap[string, int]()
	m.Put("a", 1)
	m.Put("b", 2)
	m.Put("c", 3)

	pair := m.Front()
	if pair == nil {
		t.Fatal("Expected non-nil front")
	}

	m.Remove("b")
	next := pair.Next()
	if next == nil {
		t.Fatal("Expected non-nil next after removal")
	}
	if next.Key != "c" || next.Value != 3 {
		t.Errorf("Expected {c,3}, got {%v,%v}", next.Key, next.Value)
	}
}

func TestPreviousNil(t *testing.T) {
	var pair *LhmPair[string, int]
	if prev := pair.Previous(); prev != nil {
		t.Errorf("Expected nil for nil pair, got %v", prev)
	}
}

func TestPreviousEmpty(t *testing.T) {
	m := NewLinkedHashMap[string, int]()
	pair := &LhmPair[string, int]{m: m}
	if prev := pair.Previous(); prev != nil {
		t.Errorf("Expected nil for empty map, got %v", prev)
	}
}

func TestPreviousSequence(t *testing.T) {
	m := NewLinkedHashMap[string, int]()
	m.Put("a", 1)
	m.Put("b", 2)
	m.Put("c", 3)

	expected := []struct {
		key string
		val int
	}{
		{"c", 3},
		{"b", 2},
		{"a", 1},
	}

	pair := m.Newest()
	for i, exp := range expected {
		if pair == nil {
			t.Fatalf("Step %d: Unexpected nil pair", i)
		}
		if pair.Key != exp.key || pair.Value != exp.val {
			t.Errorf("Step %d: Expected {%v,%v}, got {%v,%v}",
				i, exp.key, exp.val, pair.Key, pair.Value)
		}
		pair = pair.Previous()
	}

	if pair != nil {
		t.Error("Expected nil after first element")
	}
}

func TestPreviousAfterRemoval(t *testing.T) {
	m := NewLinkedHashMap[string, int]()
	m.Put("a", 1)
	m.Put("b", 2)
	m.Put("c", 3)

	pair := m.Newest()
	if pair == nil {
		t.Fatal("Expected non-nil newest")
	}

	m.Remove("b")
	prev := pair.Previous()
	if prev == nil {
		t.Fatal("Expected non-nil previous after removal")
	}
	if prev.Key != "a" || prev.Value != 1 {
		t.Errorf("Expected {a,1}, got {%v,%v}", prev.Key, prev.Value)
	}
}
