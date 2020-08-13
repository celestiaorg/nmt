package nmt

import (
	"github.com/lazyledger/nmt/namespace"
)

// nmtHasher provides the functions needed to compute an NMT.
// TODO: make all methods "namespaced" too (like EmptyRoot())
type nmtHasher interface {
	// EmptyRoot returns the namespaced root for a no-leaves Namespaced Merkle
	// tree.
	EmptyRoot() namespace.IntervalDigest

	// HashLeaf defines how a leaf is hashed.
	HashLeaf(leaf []byte) []byte

	// HashNode defines how a inner node is hashed.
	HashNode(l, r []byte) []byte

	// Size returns the size of the underlying hasher.
	Size() int
	// Return the size of the namespace
	NamespaceSize() uint8
}
