package tomtp

import (
	"fmt"
	"sync"
)

type LinkedHashMap[K comparable, V any] struct {
	items map[K]*LhmPair[K, V]
	head  *LhmPair[K, V]
	tail  *LhmPair[K, V]
	mu    sync.RWMutex
}

type LhmPair[K comparable, V any] struct {
	Key   K
	Value V
	m     *LinkedHashMap[K, V]
	prev  *LhmPair[K, V]
	next  *LhmPair[K, V]
}

func (p *LhmPair[K, V]) String() string {
	if k, isUint64Key := any(p.Key).(uint64); isUint64Key {
		if v, isUint64Value := any(p.Value).(uint64); isUint64Value {
			streamOffset, streamLen := GetRangeOffsetLen(k)
			return fmt.Sprintf("{Offset: %d, Len: %d,Time: %d}", streamOffset, streamLen, v)
		}
	}
	return fmt.Sprintf("{Key: %v, Value: %v}", p.Key, p.Value)
}

func NewLinkedHashMap[K comparable, V any]() *LinkedHashMap[K, V] {
	return &LinkedHashMap[K, V]{
		items: make(map[K]*LhmPair[K, V]),
	}
}

func (m *LinkedHashMap[K, V]) Size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.items)
}

func (m *LinkedHashMap[K, V]) Put(key K, value V) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if isNil(value) {
		return false
	}
	if existing, ok := m.items[key]; ok {
		existing.Value = value
		return true
	}
	newPair := &LhmPair[K, V]{
		Key:   key,
		Value: value,
		m:     m,
	}
	m.items[key] = newPair
	if m.tail == nil {
		m.head = newPair
		m.tail = newPair
	} else {
		newPair.prev = m.tail
		m.tail.next = newPair
		m.tail = newPair
	}
	return true
}

func (m *LinkedHashMap[K, V]) Get(key K) *LhmPair[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.items[key]
}

func (m *LinkedHashMap[K, V]) Remove(key K) *LhmPair[K, V] {
	m.mu.Lock()
	defer m.mu.Unlock()
	pair, ok := m.items[key]
	if !ok {
		return nil
	}
	if pair.prev != nil {
		pair.prev.next = pair.next
	} else {
		m.head = pair.next
	}
	if pair.next != nil {
		pair.next.prev = pair.prev
	} else {
		m.tail = pair.prev
	}
	delete(m.items, pair.Key)
	return pair
}

func (m *LinkedHashMap[K, V]) Oldest() *LhmPair[K, V] {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.head
}

func (p *LhmPair[K, V]) Next() *LhmPair[K, V] {
	if p == nil || p.m == nil {
		return nil
	}
	p.m.mu.RLock()
	defer p.m.mu.RUnlock()
	return p.next
}

func (p *LhmPair[K, V]) Replace(key K, value V) {
	if p == nil || p.m == nil {
		return
	}
	p.m.mu.Lock()
	defer p.m.mu.Unlock()

	fmt.Printf("Node I want to store: %v\n", value)

	oldKey := p.Key
	fmt.Printf("Before replace - oldKey: %v, items: %v\n", oldKey, p.m.items)

	p.Key = key
	p.Value = value

	fmt.Printf("During replace - newKey: %v, items: %v\n", p.Key, p.m.items)

	p.m.items[p.Key] = p
	delete(p.m.items, oldKey)

	fmt.Printf("After replace - final items: %v\n", p.m.items)
	fmt.Printf("Node I store: %v\n", p)
}
