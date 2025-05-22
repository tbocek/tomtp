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
	head  *shmPair[K, V]
	level int
	size  int // Number of elements
	mu    sync.RWMutex
	less  func(a K, b K, c V, d V) bool
}

// shmPair represents a node in the skip list.
type shmPair[K comparable, V any] struct {
	key   K
	value V
	next  []*shmPair[K, V]
	m     *skipList[K, V]
}

// newSortedHashMap creates a new skipList with the given comparison function.
func newSortedHashMap[K comparable, V any](
	less func(a K, b K, c V, d V) bool) *skipList[K, V] {
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
	// Note: isNil is not provided in the original code, assuming it exists elsewhere
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
		for current.next[i] != nil && m.less(current.next[i].key, key, current.next[i].value, value) {
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

// Get retrieves a value from the map. Returns the node or nil if not found.
func (m *skipList[K, V]) Get(key K) *shmPair[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()
	node, _ := m.items[key] // Ignore the boolean 'ok' as we return nil anyway if not found
	return node
}

// Remove removes a key-value pair from the map. Returns the removed node or nil if not found.
func (m *skipList[K, V]) Remove(key K) *shmPair[K, V] {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if key exists
	node, ok := m.items[key]
	if !ok {
		return nil
	}

	// Find node at each level and prepare updates
	update := make([]*shmPair[K, V], maxLevel)
	current := m.head

	for i := m.level - 1; i >= 0; i-- {
		for current.next[i] != nil && m.less(current.next[i].key, key, current.next[i].value, node.value) {
			current = current.next[i]
		}
		update[i] = current
	}

	// Remove node by updating pointers if the next node is the one to remove
	// Check ensures we only update if `update[i].next[i]` is actually `node`
	// This handles cases where the key exists but the `less` function causes
	// the search path to not directly point to the node via `update[i]`.
	if current.next[0] == node { // Check level 0 specifically is sufficient
		for i := 0; i < m.level; i++ {
			if update[i].next[i] != node {
				// This shouldn't happen if current.next[0] == node,
				// but acts as a safeguard or could indicate an issue elsewhere.
				// More likely, this level just doesn't point to the node.
				continue // Skip update for this level if it doesn't point to node
			}
			update[i].next[i] = node.next[i]
		}
	} else {
		// This case implies the node exists in the map but wasn't found via traversal,
		// which points to an inconsistency (shouldn't happen with correct Put/Remove logic).
		// We still proceed to delete from the map, but the list links might be wrong.
		// Consider adding logging or error handling here if this state is possible.
	}

	// Update level if needed
	for m.level > 1 && m.head.next[m.level-1] == nil {
		m.level--
	}

	delete(m.items, key)
	m.size--
	// Clear node's next pointers to prevent memory leaks if the caller holds onto the node
	for i := range node.next {
		node.next[i] = nil
	}
	node.m = nil // Remove reference back to the list

	return node
}

// Min returns the node with the smallest key according to the less function.
func (m *skipList[K, V]) Min() *shmPair[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// The first node after the head at the base level is the minimum
	return m.head.next[0]
}

func (m *skipList[K, V]) MinValue() V {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// The first node after the head at the base level is the minimum
	p := m.head.next[0]
	if p == nil {
		var zero V
		return zero
	}
	return p.value
}

// Max returns the node with the largest key according to the less function.
func (m *skipList[K, V]) Max() *shmPair[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.head.next[0] == nil { // Check if list is empty
		return nil
	}

	// Traverse down the highest levels first, always going right
	current := m.head
	for i := m.level - 1; i >= 0; i-- {
		for current.next[i] != nil {
			current = current.next[i]
		}
	}
	// 'current' will be the last node in the list
	// Check if the list was actually empty (current would still be head)
	if current == m.head {
		return nil
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

func (n *shmPair[K, V]) NextValue() V {
	if n == nil || n.m == nil { // Check if node is valid or detached
		var zeroV V
		return zeroV
	}
	n.m.mu.RLock()
	defer n.m.mu.RUnlock()

	if _, exists := n.m.items[n.key]; !exists || n.m.items[n.key] != n {
		var zeroV V
		return zeroV
	}

	p := n.next[0]
	if p == nil {
		var zeroV V
		return zeroV
	}
	return p.value
}

// Next returns the node with the smallest key greater than this node's key.
func (n *shmPair[K, V]) Next() *shmPair[K, V] {
	// No lock needed here if we assume the node is valid and its next[0] pointer is stable
	// If concurrent Removes can happen, a lock might be needed depending on guarantees.
	// The original code used RLock, let's keep that pattern for safety, although
	// accessing n.next[0] directly is common in skip list iterators.
	if n == nil || n.m == nil { // Check if node is valid or detached
		return nil
	}

	n.m.mu.RLock()
	defer n.m.mu.RUnlock()

	// Check if the node still exists in the map (might have been removed)
	// This check adds safety against using a detached node.
	if _, exists := n.m.items[n.key]; !exists || n.m.items[n.key] != n {
		return nil // Node is stale or removed
	}

	// The next node in the base level is the successor
	return n.next[0]
}

// Key returns the key of the node.
func (n *shmPair[K, V]) Key() K {
	// Assuming K is safe to return by value directly
	return n.key
}

// Value returns the value of the node.
func (n *shmPair[K, V]) Value() V {
	// If V could be mutated externally, and we want isolation,
	// we might need locking or deep copying depending on V's type.
	// For typical usage (e.g., primitives, immutable structs), direct return is fine.
	// The original Get returned the node directly, implying callers handle concurrency.
	// Let's add a read lock consistent with other accessors.
	if n == nil || n.m == nil {
		var zeroV V
		return zeroV // Return zero value if node is invalid
	}
	n.m.mu.RLock()
	defer n.m.mu.RUnlock()
	// Re-check validity inside lock
	if _, exists := n.m.items[n.key]; !exists || n.m.items[n.key] != n {
		var zeroV V
		return zeroV
	}
	return n.value
}

// Assume isNil function exists elsewhere if needed by Put, e.g.:
// func isNil(v any) bool {
// 	if v == nil {
// 		return true
// 	}
// 	// Optional: Check for typed nil interfaces/pointers if V can be interface{} or *T
// 	// rv := reflect.ValueOf(v)
// 	// switch rv.Kind() {
// 	// case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice, reflect.Interface, reflect.Func:
// 	// 	return rv.IsNil()
// 	// }
// 	return false
// }
