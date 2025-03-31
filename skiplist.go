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
	items          map[K]*shmPair[K, V]
	head           *shmPair[K, V]
	headSecondary  *shmPair[K, V]
	level          int
	levelSecondary int
	size           int // Number of elements
	mu             sync.RWMutex
	less           func(a K, b K, c V, d V) bool
	lessSecondary  func(a K, b K, c V, d V) bool
}

// shmPair represents a node in the skip list.
type shmPair[K comparable, V any] struct {
	key           K
	value         V
	next          []*shmPair[K, V]
	nextSecondary []*shmPair[K, V]
	m             *skipList[K, V]
}

// newSortedHashMap creates a new skipList with the given comparison function.
func newSortedHashMap[K comparable, V any](
	less func(a K, b K, c V, d V) bool,
	lessSecondary func(a K, b K, c V, d V) bool) *skipList[K, V] {
	m := &skipList[K, V]{
		items:          make(map[K]*shmPair[K, V]),
		level:          1,
		levelSecondary: 1,
		less:           less,
		lessSecondary:  lessSecondary,
	}
	// Create header node with maximum levels
	m.head = &shmPair[K, V]{
		next:          make([]*shmPair[K, V], maxLevel),
		nextSecondary: make([]*shmPair[K, V], maxLevel),
		m:             m,
	}
	m.headSecondary = m.head

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
	updatePrimary := make([]*shmPair[K, V], maxLevel)
	current := m.head

	// Search from top level
	for i := m.level - 1; i >= 0; i-- {
		for current.next[i] != nil && m.less(current.next[i].key, key, current.next[i].value, value) {
			current = current.next[i]
		}
		updatePrimary[i] = current
	}

	updateSecondary := make([]*shmPair[K, V], maxLevel)
	current = m.headSecondary

	for i := m.levelSecondary - 1; i >= 0; i-- {
		for current.nextSecondary[i] != nil && m.lessSecondary(current.nextSecondary[i].key, key, current.nextSecondary[i].value, value) {
			current = current.nextSecondary[i]
		}
		updateSecondary[i] = current
	}

	// Determine level for new node
	level := m.getNodeLevel()
	if level > m.level {
		for i := m.level; i < level; i++ {
			updatePrimary[i] = m.head
		}
		m.level = level
	}
	if level > m.levelSecondary {
		for i := m.levelSecondary; i < level; i++ {
			updateSecondary[i] = m.headSecondary
		}
		m.levelSecondary = level
	}

	// Create and insert new node
	newNode := &shmPair[K, V]{
		key:           key,
		value:         value,
		next:          make([]*shmPair[K, V], level),
		nextSecondary: make([]*shmPair[K, V], level),
		m:             m,
	}

	// Update pointers at each level
	for i := 0; i < level; i++ {
		newNode.next[i] = updatePrimary[i].next[i]
		updatePrimary[i].next[i] = newNode
	}
	for i := 0; i < level; i++ {
		newNode.nextSecondary[i] = updateSecondary[i].nextSecondary[i]
		updateSecondary[i].nextSecondary[i] = newNode
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
	node, ok := m.items[key]
	if !ok {
		return nil
	}

	// Find node at each level
	updatePrimary := make([]*shmPair[K, V], maxLevel)
	current := m.head

	for i := m.level - 1; i >= 0; i-- {
		for current.next[i] != nil && m.less(current.next[i].key, key, current.next[i].value, node.value) {
			current = current.next[i]
		}
		updatePrimary[i] = current
	}

	updateSecondary := make([]*shmPair[K, V], maxLevel)
	current = m.headSecondary

	for i := m.levelSecondary - 1; i >= 0; i-- {
		for current.nextSecondary[i] != nil && m.lessSecondary(current.nextSecondary[i].key, key, current.nextSecondary[i].value, node.value) {
			current = current.nextSecondary[i]
		}
		updateSecondary[i] = current
	}

	for i := 0; i < m.level; i++ {
		if updatePrimary[i].next[i] != node {
			break
		}
		updatePrimary[i].next[i] = node.next[i]
	}

	// Remove node from all levels of secondary sort
	for i := 0; i < m.levelSecondary; i++ {
		if updateSecondary[i].nextSecondary[i] != node {
			break
		}
		updateSecondary[i].nextSecondary[i] = node.nextSecondary[i]
	}

	// Update level if needed for primary sort
	for m.level > 1 && m.head.next[m.level-1] == nil {
		m.level--
	}

	// Update level if needed for secondary sort
	for m.levelSecondary > 1 && m.headSecondary.nextSecondary[m.levelSecondary-1] == nil {
		m.levelSecondary--
	}

	delete(m.items, key)
	m.size--
	return node
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

func (m *skipList[K, V]) MinSecondary() *shmPair[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.headSecondary.nextSecondary[0] == nil {
		return nil
	}
	return m.headSecondary.nextSecondary[0]
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

func (m *skipList[K, V]) MaxSecondary() *shmPair[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.headSecondary.nextSecondary[0] == nil {
		return nil
	}

	current := m.headSecondary
	for i := m.levelSecondary - 1; i >= 0; i-- {
		for current.nextSecondary[i] != nil {
			current = current.nextSecondary[i]
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

func (n *shmPair[K, V]) NextSecondary() *shmPair[K, V] {
	if n == nil || n.m == nil {
		return nil
	}

	n.m.mu.RLock()
	defer n.m.mu.RUnlock()

	return n.nextSecondary[0]
}
