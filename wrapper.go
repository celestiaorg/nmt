package nmt

import (
	"crypto/sha256"

	"github.com/lazyledger/nmt/namespace"
	"github.com/lazyledger/rsmt2d"
)

var paritySharesNamespaceID = namespace.ID{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

// Fulfills the rsmt2d.Tree interface and rsmt2d.TreeConstructorFn function
var _ rsmt2d.TreeConstructorFn = ErasuredNamespacedMerkleTree{}.Constructor
var _ rsmt2d.Tree = &ErasuredNamespacedMerkleTree{}

// ErasuredNamespacedMerkleTree wraps NamespaceMerkleTree to conform to the
// rsmt2d.Tree interface while catering specifically to erasure data. For the
// first half of the tree, it uses the first DefaultNamespaceIDLen number of
// bytes of the data pushed to determine the namespace. For the second half, it
// uses the parity namespace ID
type ErasuredNamespacedMerkleTree struct {
	squareSize uint64
	pushCount  uint64
	options    []Option
	tree       *NamespacedMerkleTree
}

// NewErasuredNamespacedMerkleTree issues a new ErasuredNamespacedMerkleTree
func NewErasuredNamespacedMerkleTree(squareSize uint64, setters ...Option) ErasuredNamespacedMerkleTree {
	return ErasuredNamespacedMerkleTree{squareSize: squareSize, options: setters}
}

// Constructor acts as the rsmt2d.TreeConstructorFn for
// ErasuredNamespacedMerkleTree
func (w ErasuredNamespacedMerkleTree) Constructor() rsmt2d.Tree {
	w.tree = New(sha256.New(), w.options...)
	return &w
}

// Push adds the provided data to the underlying NamespaceMerkleTree, and
// automatically uses the first DefaultNamespaceIDLen number of bytes as the
// namespace unless the data pushed to the second half of the tree. Fulfills the
// rsmt.Tree interface. NOTE: panics if there's an error pushing to underlying
// NamespaceMerkleTree or if the tree size is exceeded
func (w *ErasuredNamespacedMerkleTree) Push(data []byte) {
	// determine the namespace based on where in the tree we're pushing
	nsID := make(namespace.ID, DefaultNamespaceIDLen)

	switch {
	// panic if the tree size is exceeded
	case w.pushCount > 2*w.squareSize:
		panic("tree size exceeded")

	// if the namespace is included in the data, use that ns
	case w.pushCount+1 <= w.squareSize/2:
		copy(nsID, data[:DefaultNamespaceIDLen])

	// if the data is erasure data use the parity ns
	default:
		copy(nsID, paritySharesNamespaceID)
	}

	// push to the underlying tree
	err := w.tree.Push(nsID, data)
	// panic on error
	if err != nil {
		panic(err)
	}

	w.pushCount++
	return
}

// Root fulfills the rsmt.Tree interface by generating and returning a single
// leaf proof using the underlying NamespacedMerkleTree. NOTE: panics if the
// underlying NamespaceMerkleTree errors.
func (w *ErasuredNamespacedMerkleTree) Prove(idx int) (merkleRoot []byte, proofSet [][]byte, proofIndex uint64, numLeaves uint64) {
	proof, err := w.tree.Prove(idx)
	if err != nil {
		panic(err)
	}
	return w.Root(), proof.nodes, uint64(proof.start), uint64(len(proof.nodes))
}

// Root fulfills the rsmt.Tree interface by generating and returning the
// underlying NamespaceMerkleTree Root.
func (w *ErasuredNamespacedMerkleTree) Root() []byte {
	return w.tree.Root().Bytes()
}
