package nmt

import (
	"github.com/lazyledger/nmt/namespace"
)

// TODO: make all methods "namespaced" too (like EmptyRoot())
type Hasher interface {
	// EmptyRoot returns the namespaced root for a no-leafs Namespaced Merkle
	// tree.
	EmptyRoot() (minNs, maxNs namespace.ID, root []byte)

	// HashLeaf defines how a leaf is hashed.
	HashLeaf(leaf []byte) []byte

	// HashNode defines how a inner node is hashed.
	HashNode(l, r []byte) []byte

	// Size returns the size of the underlying hasher.
	Size() int
	// Return the size of the namespace
	NamespaceSize() int
}
