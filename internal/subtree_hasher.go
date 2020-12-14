package internal

import (
	"io"

	"github.com/lazyledger/merkletree"
)

type TreeHasher interface {
	merkletree.TreeHasher
	Size() int
}

// CachedSubtreeHasher implements SubtreeHasher using a set of precomputed
// leaf hashes.
type CachedSubtreeHasher struct {
	leafHashes [][]byte
	TreeHasher
}

// NextSubtreeRoot implements SubtreeHasher.
func (csh *CachedSubtreeHasher) NextSubtreeRoot(subtreeSize int) ([]byte, error) {
	if len(csh.leafHashes) == 0 {
		return nil, io.EOF
	}
	tree := merkletree.NewFromTreehasher(csh.TreeHasher)
	for i := 0; i < subtreeSize && len(csh.leafHashes) > 0; i++ {
		if err := tree.PushSubTree(0, csh.leafHashes[0]); err != nil {
			return nil, err
		}
		csh.leafHashes = csh.leafHashes[1:]
	}
	return tree.Root(), nil
}

// Skip implements SubtreeHasher.
func (csh *CachedSubtreeHasher) Skip(n int) error {
	if n > len(csh.leafHashes) {
		return io.ErrUnexpectedEOF
	}
	csh.leafHashes = csh.leafHashes[n:]
	return nil
}

// NewCachedSubtreeHasher creates a CachedSubtreeHasher using the specified
// leaf hashes and hash function.
func NewCachedSubtreeHasher(leafHashes [][]byte, h TreeHasher) *CachedSubtreeHasher {
	return &CachedSubtreeHasher{
		leafHashes: leafHashes,
		TreeHasher: h,
	}
}
