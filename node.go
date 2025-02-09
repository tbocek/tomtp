package tomtp

import (
	"errors"
	"fmt"
	"sync"
)

type Node[K comparable, V any] struct {
	Key    K
	Value  V
	Parent *Node[K, V]
	Left   *Node[K, V]
	Right  *Node[K, V]
	shadow bool
	mu     sync.RWMutex
}

func (n *Node[K, V]) String() string {
	if k, isUint64Key := any(n.Key).(uint64); isUint64Key {
		if v, isUint64Value := any(n.Value).(uint64); isUint64Value {
			streamOffset, streamLen := GetRangeOffsetLen(k)
			return fmt.Sprintf("{Offset: %d, Len: %d,Time: %d}", streamOffset, streamLen, v)
		}
	}
	return fmt.Sprintf("{key: %v, value: %v}", n.Key, n.Value)
}

func NewNode[K comparable, V any](key K, value V) *Node[K, V] {
	return &Node[K, V]{Key: key, Value: value}
}

func (n *Node[K, V]) IsShadow() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.shadow
}

func (n *Node[K, V]) Split(leftKey K, leftValue V, rightKey K, rightValue V) (*Node[K, V], *Node[K, V]) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.shadow {
		panic(errors.New("cannot split a shadowed node"))
	}
	n.shadow = true
	left := NewNode(leftKey, leftValue)
	right := NewNode(rightKey, rightValue)

	n.Left = left
	n.Right = right
	left.Parent = n
	right.Parent = n

	return left, right
}

func (n *Node[K, V]) removeDown() []K {
	if n == nil {
		return nil
	}
	keys := make([]K, 0)

	// Store references before clearing
	left := n.Left
	right := n.Right

	// Clear references first
	n.Left = nil
	n.Right = nil

	// Then process children
	if left != nil {
		leftKeys := left.removeDown()
		keys = append(keys, leftKeys...)
		keys = append(keys, left.Key)
	}
	if right != nil {
		rightKeys := right.removeDown()
		keys = append(keys, rightKeys...)
		keys = append(keys, right.Key)
	}

	return keys
}

func (n *Node[K, V]) removeUp() []K {
	if n == nil {
		return nil
	}
	keys := make([]K, 0)

	// Store reference before clearing
	parent := n.Parent
	wasLeft := parent != nil && parent.Left == n

	// Break parent link
	if parent != nil {
		if parent.Left == n {
			parent.Left = nil
		}
		if parent.Right == n {
			parent.Right = nil
		}
	}
	n.Parent = nil

	// Process parent if we were left child
	if wasLeft {
		parentKeys := parent.removeUp()
		keys = append(keys, parentKeys...)
		keys = append(keys, parent.Key)
	}

	return keys
}

func (n *Node[K, V]) Remove() []K {
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
	keys = append(keys, n.Key)

	return keys
}
