// Package tomtp provides data structure implementations.
// All exported methods (those starting with capital letters) are thread-safe.
package tomtp

import (
	"sync"
)

// sortedHashMap implements a thread-safe binary search tree with hash map lookup.
// It maintains both a BST for ordered operations and a hash map for O(1) lookups.
type sortedHashMap[K comparable, V any] struct {
	items map[K]*shmPair[K, V]
	root  *shmPair[K, V]
	mu    sync.RWMutex
	less  func(a, b K) bool
}

// shmPair represents a node in the binary search tree.
type shmPair[K comparable, V any] struct {
	key    K
	value  V
	left   *shmPair[K, V]
	right  *shmPair[K, V]
	parent *shmPair[K, V]
	m      *sortedHashMap[K, V]
}

// newSortedHashMap creates a new sortedHashMap with the given comparison function.
func newSortedHashMap[K comparable, V any](less func(a, b K) bool) *sortedHashMap[K, V] {
	return &sortedHashMap[K, V]{
		items: make(map[K]*shmPair[K, V]),
		less:  less,
	}
}

// Size returns the number of elements in the map.
func (m *sortedHashMap[K, V]) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.items)
}

// Put adds or updates a key-value pair in the map.
// Returns true if successful, false if the value is nil.
func (m *sortedHashMap[K, V]) Put(key K, value V) bool {
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

	// Create new node
	newNode := &shmPair[K, V]{
		key:   key,
		value: value,
		m:     m,
	}
	m.items[key] = newNode

	// Handle empty tree case
	if m.root == nil {
		m.root = newNode
		return true
	}

	// Find insertion point
	current := m.root
	var parent *shmPair[K, V]
	var isLeft bool
	for current != nil {
		parent = current
		if m.less(key, current.key) {
			current = current.left
			isLeft = true
		} else {
			current = current.right
			isLeft = false
		}
	}

	// Insert node
	newNode.parent = parent
	if isLeft {
		parent.left = newNode
	} else {
		parent.right = newNode
	}
	return true
}

// Get retrieves a value from the map.
// Returns the node if found, nil otherwise.
func (m *sortedHashMap[K, V]) Get(key K) *shmPair[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.items[key]
}

// Remove removes a key-value pair from the map.
// Returns the removed node if found, nil otherwise.
func (m *sortedHashMap[K, V]) Remove(key K) *shmPair[K, V] {
	m.mu.Lock()
	defer m.mu.Unlock()

	node, ok := m.items[key]
	if !ok {
		return nil
	}

	delete(m.items, key)

	// Case 1: No left child
	if node.left == nil {
		m.transplant(node, node.right)
	} else if node.right == nil {
		// Case 2: No right child
		m.transplant(node, node.left)
	} else {
		// Case 3: Two children
		successor := m.minimum(node.right)
		if successor.parent != node {
			m.transplant(successor, successor.right)
			successor.right = node.right
			successor.right.parent = successor
		}
		m.transplant(node, successor)
		successor.left = node.left
		successor.left.parent = successor
	}
	return node
}

// minimum returns the node with the smallest key in the subtree rooted at x.
func (m *sortedHashMap[K, V]) minimum(x *shmPair[K, V]) *shmPair[K, V] {
	for x.left != nil {
		x = x.left
	}
	return x
}

// transplant replaces the subtree rooted at node u with the subtree rooted at node v.
func (m *sortedHashMap[K, V]) transplant(u, v *shmPair[K, V]) {
	if u.parent == nil {
		m.root = v
	} else if u == u.parent.left {
		u.parent.left = v
	} else {
		u.parent.right = v
	}
	if v != nil {
		v.parent = u.parent
	}
}

// Min returns the node with the smallest key in the tree.
// Returns nil if the tree is empty.
func (m *sortedHashMap[K, V]) Min() *shmPair[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.root == nil {
		return nil
	}
	return m.minimum(m.root)
}

// Max returns the node with the largest key in the tree.
// Returns nil if the tree is empty.
func (m *sortedHashMap[K, V]) Max() *shmPair[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.root == nil {
		return nil
	}
	current := m.root
	for current.right != nil {
		current = current.right
	}
	return current
}

// Contains checks if a key exists in the map.
func (m *sortedHashMap[K, V]) Contains(key K) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.items[key]
	return exists
}

// Next returns the node with the smallest key greater than this node's key.
// Returns nil if there is no such node or if the node or map is nil.
func (n *shmPair[K, V]) Next() *shmPair[K, V] {
	if n == nil || n.m == nil {
		return nil
	}

	n.m.mu.RLock()
	defer n.m.mu.RUnlock()

	// Case 1: Right subtree exists
	if n.right != nil {
		return n.m.minimum(n.right)
	}

	// Case 2: No right subtree - find first right parent
	current := n
	parent := n.parent
	for parent != nil && current == parent.right {
		current = parent
		parent = parent.parent
	}
	return parent
}
