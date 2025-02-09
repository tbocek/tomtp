package tomtp

import (
	"errors"
	"sync"
)

type node[K comparable, V any] struct {
	key    K
	value  V
	parent *node[K, V]
	left   *node[K, V]
	right  *node[K, V]
	shadow bool
	mu     sync.RWMutex
}

func newNode[K comparable, V any](key K, value V) *node[K, V] {
	return &node[K, V]{key: key, value: value}
}

func (n *node[K, V]) IsShadow() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.shadow
}

func (n *node[K, V]) Split(leftKey K, leftValue V, rightKey K, rightValue V) (*node[K, V], *node[K, V]) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.shadow {
		panic(errors.New("cannot split a shadowed node"))
	}
	n.shadow = true
	left := newNode(leftKey, leftValue)
	right := newNode(rightKey, rightValue)

	n.left = left
	n.right = right
	left.parent = n
	right.parent = n

	return left, right
}

func (n *node[K, V]) removeDown() []K {
	if n == nil {
		return nil
	}
	keys := make([]K, 0)

	// Store references before clearing
	left := n.left
	right := n.right

	// Clear references first
	n.left = nil
	n.right = nil

	// Then process children
	if left != nil {
		leftKeys := left.removeDown()
		keys = append(keys, leftKeys...)
		keys = append(keys, left.key)
	}
	if right != nil {
		rightKeys := right.removeDown()
		keys = append(keys, rightKeys...)
		keys = append(keys, right.key)
	}

	return keys
}

func (n *node[K, V]) removeUp() []K {
	if n == nil {
		return nil
	}
	keys := make([]K, 0)

	// Store reference before clearing
	parent := n.parent
	wasLeft := parent != nil && parent.left == n

	// Break parent link
	if parent != nil {
		if parent.left == n {
			parent.left = nil
		}
		if parent.right == n {
			parent.right = nil
		}
	}
	n.parent = nil

	// Process parent if we were left child
	if wasLeft {
		parentKeys := parent.removeUp()
		keys = append(keys, parentKeys...)
		keys = append(keys, parent.key)
	}

	return keys
}

func (n *node[K, V]) Remove() []K {
	if n == nil {
		return nil
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	downKeys := n.removeDown()
	upKeys := n.removeUp()

	keys := make([]K, 0, len(downKeys)+len(upKeys)+1)
	keys = append(keys, downKeys...)
	keys = append(keys, upKeys...)
	keys = append(keys, n.key)

	return keys
}
