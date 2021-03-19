package nmt

import (
	"testing"

	"github.com/lazyledger/rsmt2d"
)

const (
	shareSize           = 256
	adjustedMessageSize = shareSize - DefaultNamespaceIDLen
)

func TestPushErasuredNamespacedMerkleTree(t *testing.T) {
	testCases := []struct {
		name       string
		squareSize int
	}{
		{"extendedSquareSize = 16", 8},
		{"extendedSquareSize = 256", 128},
	}
	for _, tc := range testCases {
		tc := tc
		n := NewErasuredNamespacedMerkleTree(uint64(tc.squareSize))
		tree := n.Constructor()

		// push test data to the tree
		for _, d := range generateErasuredData(t, tc.squareSize) {
			// push will panic if there's an error
			tree.Push(d)
		}
	}
}

func generateErasuredData(t *testing.T, numLeaves int) [][]byte {
	raw := generateRandNamespacedRawData(
		numLeaves,
		DefaultNamespaceIDLen,
		adjustedMessageSize,
	)
	erasuredData, err := rsmt2d.Encode(raw, rsmt2d.RSGF8)
	if err != nil {
		t.Error(err)
	}
	return append(raw, erasuredData...)
}
