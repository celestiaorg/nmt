package treehasher

import (
	"github.com/lazyledger/nmt/namespace"
)

// TODO: make all methods "namespaced" too (like EmptyRoot())
type NmTreeHasher interface {
	// EmptyRoot returns the namespaced root for a no-leafs Namespaced Merkle tree.
	// This can be used to define whatever
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
