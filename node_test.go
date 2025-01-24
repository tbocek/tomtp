package tomtp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNodeCreation(t *testing.T) {
	node := NewNode[uint64, uint64](1, 100)
	assert.Equal(t, uint64(1), node.Key)
	assert.Equal(t, uint64(100), node.Value)
	assert.Nil(t, node.Parent)
	assert.Nil(t, node.Left)
	assert.Nil(t, node.Right)
	assert.False(t, node.shadow)
}

func TestNodeSplit(t *testing.T) {
	parent := NewNode[uint64, uint64](1, 100)
	left, right := parent.Split(2, 200, 3, 300)

	assert.True(t, parent.shadow)
	assert.Equal(t, uint64(2), left.Key)
	assert.Equal(t, uint64(200), left.Value)
	assert.Equal(t, uint64(3), right.Key)
	assert.Equal(t, uint64(300), right.Value)

	assert.Equal(t, parent, left.Parent)
	assert.Equal(t, parent, right.Parent)
	assert.Equal(t, left, parent.Left)
	assert.Equal(t, right, parent.Right)
}

func TestNodeSplitPanic(t *testing.T) {
	parent := NewNode[uint64, uint64](1, 100)
	parent.shadow = true
	assert.Panics(t, func() {
		parent.Split(2, 200, 3, 300)
	})
}

func TestNodeRemove(t *testing.T) {
	tests := []struct {
		name  string
		setup func() (*Node[uint64, uint64], []uint64)
	}{
		{
			name: "Remove single node",
			setup: func() (*Node[uint64, uint64], []uint64) {
				node := NewNode[uint64, uint64](1, 100)
				return node, []uint64{1}
			},
		},
		{
			name: "Remove parent and children",
			setup: func() (*Node[uint64, uint64], []uint64) {
				parent := NewNode[uint64, uint64](1, 100)
				parent.Split(2, 200, 3, 300)
				return parent, []uint64{1, 2, 3}
			},
		},
		{
			name: "Remove left child and parent",
			setup: func() (*Node[uint64, uint64], []uint64) {
				parent := NewNode[uint64, uint64](1, 100)
				left, _ := parent.Split(2, 200, 3, 300)
				return left, []uint64{1, 2}
			},
		},
		{
			name: "Remove right child only",
			setup: func() (*Node[uint64, uint64], []uint64) {
				parent := NewNode[uint64, uint64](1, 100)
				_, right := parent.Split(2, 200, 3, 300)
				return right, []uint64{3}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, expectedKeys := tt.setup()
			keys := node.Remove()
			assert.ElementsMatch(t, expectedKeys, keys)

			// Verify cleanup
			if node.Parent != nil {
				assert.NotEqual(t, node, node.Parent.Left)
				assert.NotEqual(t, node, node.Parent.Right)
			}
			assert.Nil(t, node.Left)
			assert.Nil(t, node.Right)
		})
	}
}

func TestNodeRemoveComplex(t *testing.T) {
	tests := []struct {
		name       string
		setupTree  func() (*Node[int, string], *Node[int, string])
		removeNode func(*Node[int, string]) *Node[int, string]
		expectKeys []int
	}{
		{
			name: "Remove root node",
			setupTree: func() (*Node[int, string], *Node[int, string]) {
				root := NewNode(1, "root")
				root.Split(2, "left", 3, "right")
				return root, root
			},
			removeNode: func(root *Node[int, string]) *Node[int, string] {
				return root
			},
			expectKeys: []int{2, 3, 1},
		},
		{
			name: "Remove left child",
			setupTree: func() (*Node[int, string], *Node[int, string]) {
				root := NewNode(1, "root")
				left, _ := root.Split(2, "left", 3, "right")
				return root, left
			},
			removeNode: func(root *Node[int, string]) *Node[int, string] {
				return root.Left
			},
			expectKeys: []int{1, 2},
		},
		{
			name: "Remove right child",
			setupTree: func() (*Node[int, string], *Node[int, string]) {
				root := NewNode(1, "root")
				_, right := root.Split(2, "left", 3, "right")
				return root, right
			},
			removeNode: func(root *Node[int, string]) *Node[int, string] {
				return root.Right
			},
			expectKeys: []int{3},
		},
		{
			name: "Deep tree - remove middle left node",
			setupTree: func() (*Node[int, string], *Node[int, string]) {
				root := NewNode(1, "root")
				left, right := root.Split(2, "left", 3, "right")
				leftLeft, _ := left.Split(4, "leftleft", 5, "leftright")
				right.Split(6, "rightleft", 7, "rightright")
				return root, leftLeft
			},
			removeNode: func(root *Node[int, string]) *Node[int, string] {
				return root.Left.Left
			},
			expectKeys: []int{1, 2, 4},
		},
		{
			name: "Deep tree - remove middle right node",
			setupTree: func() (*Node[int, string], *Node[int, string]) {
				root := NewNode(1, "root")
				left, right := root.Split(2, "left", 3, "right")
				left.Split(4, "leftleft", 5, "leftright")
				rightLeft, _ := right.Split(6, "rightleft", 7, "rightright")
				return root, rightLeft
			},
			removeNode: func(root *Node[int, string]) *Node[int, string] {
				return root.Right.Left
			},
			expectKeys: []int{3, 6},
		},
		{
			name: "Deep tree - remove leaf after multiple splits",
			setupTree: func() (*Node[int, string], *Node[int, string]) {
				root := NewNode(1, "root")
				left, _ := root.Split(2, "left", 3, "right")
				leftLeft, _ := left.Split(4, "leftleft", 5, "leftright")
				target, _ := leftLeft.Split(6, "leafleft", 7, "leafright")
				return root, target
			},
			removeNode: func(root *Node[int, string]) *Node[int, string] {
				return root.Left.Left.Left
			},
			expectKeys: []int{1, 2, 4, 6},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, targetNode := tt.setupTree()
			assert.NotNil(t, targetNode)

			keys := tt.removeNode(root).Remove()
			assert.ElementsMatch(t, tt.expectKeys, keys)
		})
	}
}

func TestNodeShadowBehavior(t *testing.T) {
	root := NewNode(1, "root")
	assert.False(t, root.shadow)

	left, right := root.Split(2, "left", 3, "right")
	assert.True(t, root.shadow)
	assert.False(t, left.shadow)
	assert.False(t, right.shadow)

	assert.Panics(t, func() {
		root.Split(4, "newleft", 5, "newright")
	})
}

func TestNodeNilHandling(t *testing.T) {
	var nilNode *Node[int, string]
	assert.Empty(t, nilNode.Remove())
	assert.Empty(t, nilNode.removeDown())
	assert.Empty(t, nilNode.removeUp())
}
