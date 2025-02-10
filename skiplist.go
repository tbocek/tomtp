// Package tomtp provides dataToSend structure implementations.
// All exported methods (those starting with capital letters) are thread-safe.
package tomtp

import (
	"sync"
)

const maxLevel = 32     // Enough for 2^32 elements
const nodesPerLevel = 4 // Every 4 nodes we add a level up

// skipList implements a thread-safe deterministic skip list with hash map lookup.
type skipList[K comparable, V any] struct {
	items map[K]*shmPair[K, V]
	head  *shmPair[K, V] // Skip list header
	level int            // Current maximum level
	size  int            // Number of elements
	mu    sync.RWMutex
	less  func(a, b K) bool
}

// shmPair represents a node in the skip list.
type shmPair[K comparable, V any] struct {
	key   K
	value V
	next  []*shmPair[K, V] // Array of next pointers for each level
	m     *skipList[K, V]
}

// newSortedHashMap creates a new skipList with the given comparison function.
func newSortedHashMap[K comparable, V any](less func(a, b K) bool) *skipList[K, V] {
	m := &skipList[K, V]{
		items: make(map[K]*shmPair[K, V]),
		level: 1,
		less:  less,
	}
	// Create header node with maximum levels
	m.head = &shmPair[K, V]{
		next: make([]*shmPair[K, V], maxLevel),
		m:    m,
	}
	return m
}

// getNodeLevel returns the level a node should have based on its position
func (m *skipList[K, V]) getNodeLevel() int {
	// Count trailing zeros in size+1 divided by nodesPerLevel
	// This creates a pattern like: 1,1,1,1,2,2,2,2,3,3,3,3...
	pos := m.size + 1
	level := 1
	for pos%nodesPerLevel == 0 {
		level++
		pos /= nodesPerLevel
	}
	if level > maxLevel {
		level = maxLevel
	}
	return level
}

// Size returns the number of elements in the map.
func (m *skipList[K, V]) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.size
}

// Put adds or updates a key-value pair in the map.
func (m *skipList[K, V]) Put(key K, value V) bool {
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

	// Find insert position at each level
	update := make([]*shmPair[K, V], maxLevel)
	current := m.head

	// Search from top level
	for i := m.level - 1; i >= 0; i-- {
		for current.next[i] != nil && m.less(current.next[i].key, key) {
			current = current.next[i]
		}
		update[i] = current
	}

	// Determine level for new node
	level := m.getNodeLevel()
	if level > m.level {
		for i := m.level; i < level; i++ {
			update[i] = m.head
		}
		m.level = level
	}

	// Create and insert new node
	newNode := &shmPair[K, V]{
		key:   key,
		value: value,
		next:  make([]*shmPair[K, V], level),
		m:     m,
	}

	// Update pointers at each level
	for i := 0; i < level; i++ {
		newNode.next[i] = update[i].next[i]
		update[i].next[i] = newNode
	}

	m.items[key] = newNode
	m.size++
	return true
}

// Get retrieves a value from the map.
func (m *skipList[K, V]) Get(key K) *shmPair[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.items[key]
}

// Remove removes a key-value pair from the map.
func (m *skipList[K, V]) Remove(key K) *shmPair[K, V] {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if key exists
	_, ok := m.items[key]
	if !ok {
		return nil
	}

	// Find node at each level
	update := make([]*shmPair[K, V], maxLevel)
	current := m.head

	for i := m.level - 1; i >= 0; i-- {
		for current.next[i] != nil && m.less(current.next[i].key, key) {
			current = current.next[i]
		}
		update[i] = current
	}

	// Remove node from all levels
	current = current.next[0]
	if current != nil && current.key == key {
		for i := 0; i < m.level; i++ {
			if update[i].next[i] != current {
				break
			}
			update[i].next[i] = current.next[i]
		}

		// Update level if needed
		for m.level > 1 && m.head.next[m.level-1] == nil {
			m.level--
		}

		delete(m.items, key)
		m.size--
		return current
	}

	return nil
}

// Min returns the node with the smallest key.
func (m *skipList[K, V]) Min() *shmPair[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.head.next[0] == nil {
		return nil
	}
	return m.head.next[0]
}

// Max returns the node with the largest key.
func (m *skipList[K, V]) Max() *shmPair[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.head.next[0] == nil {
		return nil
	}

	current := m.head
	for i := m.level - 1; i >= 0; i-- {
		for current.next[i] != nil {
			current = current.next[i]
		}
	}
	return current
}

// Contains checks if a key exists in the map.
func (m *skipList[K, V]) Contains(key K) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.items[key]
	return exists
}

// Next returns the node with the smallest key greater than this node's key.
func (n *shmPair[K, V]) Next() *shmPair[K, V] {
	if n == nil || n.m == nil {
		return nil
	}

	n.m.mu.RLock()
	defer n.m.mu.RUnlock()

	return n.next[0]
}
