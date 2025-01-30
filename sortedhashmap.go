package tomtp

import (
	"sync"
)

type SortedHashMap[K comparable, V any] struct {
	items map[K]*ShmPair[K, V]
	root  *ShmPair[K, V]
	mu    sync.RWMutex
	less  func(a, b K) bool
}

type ShmPair[K comparable, V any] struct {
	Key    K
	Value  V
	left   *ShmPair[K, V]
	right  *ShmPair[K, V]
	parent *ShmPair[K, V]
	m      *SortedHashMap[K, V]
}

func NewSortedHashMap[K comparable, V any](less func(a, b K) bool) *SortedHashMap[K, V] {
	return &SortedHashMap[K, V]{
		items: make(map[K]*ShmPair[K, V]),
		less:  less,
	}
}

func (m *SortedHashMap[K, V]) Size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.items)
}

func (m *SortedHashMap[K, V]) Put(key K, value V) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if isNil(value) {
		return false
	}

	if existing, ok := m.items[key]; ok {
		existing.Value = value
		return true
	}

	newNode := &ShmPair[K, V]{
		Key:   key,
		Value: value,
		m:     m,
	}
	m.items[key] = newNode

	if m.root == nil {
		m.root = newNode
		return true
	}

	current := m.root
	var parent *ShmPair[K, V]
	var isLeft bool

	for current != nil {
		parent = current
		if m.less(key, current.Key) {
			current = current.left
			isLeft = true
		} else {
			current = current.right
			isLeft = false
		}
	}

	newNode.parent = parent
	if isLeft {
		parent.left = newNode
	} else {
		parent.right = newNode
	}

	return true
}

func (m *SortedHashMap[K, V]) Get(key K) *ShmPair[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.items[key]
}

func (m *SortedHashMap[K, V]) Remove(key K) *ShmPair[K, V] {
	m.mu.Lock()
	defer m.mu.Unlock()

	node, ok := m.items[key]
	if !ok {
		return nil
	}

	delete(m.items, key)

	if node.left == nil {
		m.transplant(node, node.right)
	} else if node.right == nil {
		m.transplant(node, node.left)
	} else {
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

func (m *SortedHashMap[K, V]) minimum(x *ShmPair[K, V]) *ShmPair[K, V] {
	for x.left != nil {
		x = x.left
	}
	return x
}

func (m *SortedHashMap[K, V]) transplant(u, v *ShmPair[K, V]) {
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

func (m *SortedHashMap[K, V]) Min() *ShmPair[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.root == nil {
		return nil
	}
	return m.minimum(m.root)
}

func (m *SortedHashMap[K, V]) Max() *ShmPair[K, V] {
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

func (m *SortedHashMap[K, V]) Contains(key K) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.items[key]
	return exists
}

func (n *ShmPair[K, V]) Next() *ShmPair[K, V] {
	if n == nil || n.m == nil {
		return nil
	}

	n.m.mu.RLock()
	defer n.m.mu.RUnlock()

	if n.right != nil {
		return n.m.minimum(n.right)
	}

	current := n
	parent := n.parent
	for parent != nil && current == parent.right {
		current = parent
		parent = parent.parent
	}

	return parent
}
