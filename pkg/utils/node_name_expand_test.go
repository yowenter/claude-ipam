package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNodeNameExpand(t *testing.T) {
	nodes, err := ExpandNodeName("node1")
	if err != nil {
		panic(err)
	}
	assert.Equal(t, len(nodes), 1)
	assert.Equal(t, nodes[0], "node1")

	nodes, err = ExpandNodeName("node[1-3]")
	if err != nil {
		panic(err)
	}
	assert.Equal(t, len(nodes), 3)
	assert.Equal(t, nodes[2], "node3")

	nodes, err = ExpandNodeName("node[1-3,4-8]")
	if err != nil {
		panic(err)
	}
	assert.Equal(t, len(nodes), 8)
	assert.Equal(t, nodes[7], "node8")

}
