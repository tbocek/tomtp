// Package tomtp provides a concurrent-safe linked hash map implementation.
// All exported methods are thread-safe.
package tomtp

import (
	"fmt"
	"sync"
)

// linkedHashMap is a concurrent-safe map that preserves insertion order.
type linkedHashMap[K comparable, V any] struct {
	items map[K]*lhmPair[K, V]
	head  *lhmPair[K, V]
	tail  *lhmPair[K, V]
	mu    sync.RWMutex
}

// lhmPair represents a key-value pair in the linkedHashMap's doubly-linked list.
type lhmPair[K comparable, V any] struct {
	key   K
	value V
	prev  *lhmPair[K, V]
	nxt   *lhmPair[K, V]
	m     *linkedHashMap[K, V]
}

// String returns a string representation of the pair.
// Special handling for uint64 values to format them as timestamps.
func (p *lhmPair[K, V]) String() string {
	if v, isUint64Value := any(p.value).(uint64); isUint64Value {
		return fmt.Sprintf("{Time: %d}", v)
	}
	return fmt.Sprintf("{value: %v}", p.value)
}

// newLinkedHashMap creates a new empty linkedHashMap.
func newLinkedHashMap[K comparable, V any]() *linkedHashMap[K, V] {
	return &linkedHashMap[K, V]{
		items: make(map[K]*lhmPair[K, V]),
	}
}

// Size returns the number of elements in the map.
func (m *linkedHashMap[K, V]) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.items)
}

// Put adds or updates a key-value pair in the map.
// Returns true if the operation was successful, false if the value is nil.
func (m *linkedHashMap[K, V]) Put(key K, value V) bool {
	if isNil(value) {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Update existing value if key exists
	if existing, ok := m.items[key]; ok {
		existing.value = value
		return true
	}

	// Create and insert new pair
	newPair := &lhmPair[K, V]{
		key:   key,
		value: value,
		m:     m,
	}
	m.items[key] = newPair

	// Update linked list
	if m.head == nil {
		m.head = newPair
		m.tail = newPair
	} else {
		newPair.prev = m.tail
		m.tail.nxt = newPair
		m.tail = newPair
	}
	return true
}

// Get retrieves a value from the map.
// Returns the pair if found, nil otherwise.
func (m *linkedHashMap[K, V]) Get(key K) *lhmPair[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.items[key]
}

// Remove removes a key-value pair from the map.
// Returns the removed pair if found, nil otherwise.
func (m *linkedHashMap[K, V]) Remove(key K) *lhmPair[K, V] {
	m.mu.Lock()
	defer m.mu.Unlock()

	pair, ok := m.items[key]
	if !ok {
		return nil
	}

	// Update linked list
	if pair.prev != nil {
		pair.prev.nxt = pair.nxt
	} else {
		m.head = pair.nxt
	}
	if pair.nxt != nil {
		pair.nxt.prev = pair.prev
	} else {
		m.tail = pair.prev
	}

	delete(m.items, key)
	return pair
}

// Oldest returns the Oldest (first inserted) pair in the map.
// Returns nil if the map is empty.
func (m *linkedHashMap[K, V]) Oldest() *lhmPair[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.head
}

// Next returns the Next pair in the linked list.
// Returns nil if there is no Next pair or if the pair or map is nil.
func (p *lhmPair[K, V]) Next() *lhmPair[K, V] {
	if p == nil || p.m == nil {
		return nil
	}

	p.m.mu.RLock()
	defer p.m.mu.RUnlock()
	return p.nxt
}

// Replace updates the key and value of an existing pair in the map.
// Does not change the prev/Next ordering.
// No effect if the pair or map is nil.
func (p *lhmPair[K, V]) Replace(key K, value V) {
	if p == nil || p.m == nil {
		return
	}

	p.m.mu.Lock()
	defer p.m.mu.Unlock()

	oldKey := p.key
	p.key = key
	p.value = value
	p.m.items[key] = p
	delete(p.m.items, oldKey)
}
