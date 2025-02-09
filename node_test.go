package tomtp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testNode groups all node-related tests
type testNode struct {
	*node[int, string]
	t *testing.T
}

func newTestNode(t *testing.T, key int, value string) *testNode {
	return &testNode{
		node: newNode(key, value),
		t:    t,
	}
}

func (n *testNode) assertLinks(parent, left, right *node[int, string]) {
	assert.Equal(n.t, parent, n.parent, "unexpected parent link")
	assert.Equal(n.t, left, n.left, "unexpected left link")
	assert.Equal(n.t, right, n.right, "unexpected right link")
}

func TestNodeBasics(t *testing.T) {
	t.Run("creation", func(t *testing.T) {
		node := newNode[uint64, uint64](1, 100)
		require.NotNil(t, node)
		assert.Equal(t, uint64(1), node.key)
		assert.Equal(t, uint64(100), node.value)
		assert.False(t, node.shadow)
		assert.Nil(t, node.parent)
		assert.Nil(t, node.left)
		assert.Nil(t, node.right)
	})
}

func TestNodeSplit(t *testing.T) {
	t.Run("successful split", func(t *testing.T) {
		parent := newTestNode(t, 1, "parent")
		left, right := parent.Split(2, "left", 3, "right")
		require.NotNil(t, left)
		require.NotNil(t, right)

		// Check parent state
		assert.True(t, parent.shadow)
		parent.assertLinks(nil, left, right)

		// Check left child
		assert.Equal(t, 2, left.key)
		assert.Equal(t, "left", left.value)
		assert.False(t, left.shadow)
		assert.Equal(t, parent.node, left.parent)

		// Check right child
		assert.Equal(t, 3, right.key)
		assert.Equal(t, "right", right.value)
		assert.False(t, right.shadow)
		assert.Equal(t, parent.node, right.parent)
	})

	t.Run("split shadowed node", func(t *testing.T) {
		parent := newTestNode(t, 1, "parent")
		parent.shadow = true
		assert.Panics(t, func() {
			parent.Split(2, "left", 3, "right")
		})
	})
}

func TestNodeRemove(t *testing.T) {
	tests := []struct {
		name       string
		buildTree  func(t *testing.T) (*testNode, []int)
		verifyTree func(t *testing.T, node *testNode)
	}{
		{
			name: "single node",
			buildTree: func(t *testing.T) (*testNode, []int) {
				return newTestNode(t, 1, "root"), []int{1}
			},
			verifyTree: func(t *testing.T, node *testNode) {
				node.assertLinks(nil, nil, nil)
			},
		},
		{
			name: "parent with children",
			buildTree: func(t *testing.T) (*testNode, []int) {
				parent := newTestNode(t, 1, "parent")
				parent.Split(2, "left", 3, "right")
				return parent, []int{1, 2, 3}
			},
			verifyTree: func(t *testing.T, node *testNode) {
				node.assertLinks(nil, nil, nil)
				assert.True(t, node.shadow)
			},
		},
		{
			name: "left child removal",
			buildTree: func(t *testing.T) (*testNode, []int) {
				parent := newTestNode(t, 1, "parent")
				left, _ := parent.Split(2, "left", 3, "right")
				return &testNode{node: left, t: t}, []int{1, 2}
			},
			verifyTree: func(t *testing.T, node *testNode) {
				node.assertLinks(nil, nil, nil)
				if node.parent != nil {
					assert.NotEqual(t, node.node, node.parent.left)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, expectedKeys := tt.buildTree(t)
			keys := node.Remove()
			assert.ElementsMatch(t, expectedKeys, keys)
			tt.verifyTree(t, node)
		})
	}
}

func TestComplexTreeOperations(t *testing.T) {
	t.Run("deep tree removal", func(t *testing.T) {
		tests := []struct {
			name       string
			buildTree  func(t *testing.T) (*testNode, *node[int, string], []int)
			verifyTree func(t *testing.T, root, removed *node[int, string])
		}{
			{
				name: "remove middle node",
				buildTree: func(t *testing.T) (*testNode, *node[int, string], []int) {
					root := newTestNode(t, 1, "root")
					left, _ := root.Split(2, "left", 3, "right")
					target, _ := left.Split(4, "target", 5, "sibling")
					return root, target, []int{1, 2, 4}
				},
				verifyTree: func(t *testing.T, root, removed *node[int, string]) {
					assert.Nil(t, removed.parent)
					assert.Nil(t, removed.left)
					assert.Nil(t, removed.right)
				},
			},
			{
				name: "remove leaf node",
				buildTree: func(t *testing.T) (*testNode, *node[int, string], []int) {
					root := newTestNode(t, 1, "root")
					left, _ := root.Split(2, "left", 3, "right")
					_, target := left.Split(4, "sibling", 5, "target")
					return root, target, []int{5}
				},
				verifyTree: func(t *testing.T, root, removed *node[int, string]) {
					assert.Nil(t, removed.parent)
					assert.Nil(t, removed.left)
					assert.Nil(t, removed.right)
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				root, targetNode, expectedKeys := tt.buildTree(t)
				keys := targetNode.Remove()
				assert.ElementsMatch(t, expectedKeys, keys)
				tt.verifyTree(t, root.node, targetNode)
			})
		}
	})
}

func TestEdgeCases(t *testing.T) {
	t.Run("nil node operations", func(t *testing.T) {
		var nilNode *node[int, string]
		assert.Empty(t, nilNode.Remove())
		// Note: isShadow() is not safe for nil receivers, so we don't test it
	})

	t.Run("concurrent operations", func(t *testing.T) {
		node := newNode(1, "test")
		done := make(chan bool)

		// Concurrent reads of shadow state
		for i := 0; i < 10; i++ {
			go func() {
				_ = node.IsShadow()
				done <- true
			}()
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}
	})
}
