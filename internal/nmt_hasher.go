package internal

import "github.com/lazyledger/nmt/namespace"

// NmtHasher provides the functions needed to compute an NMT.
// NmtHasher provides the functions needed to compute an NMT.
type NmtHasher interface {
	// EmptyRoot returns the namespaced root for a no-leaves Namespaced Merkle
	// tree.
	EmptyRoot() []byte

	// HashLeaf defines how a leaf is hashed.
	HashLeaf(leaf []byte) []byte

	// HashNode defines how a inner node is hashed.
	HashNode(l, r []byte) []byte

	// Size returns the size of the underlying hasher.
	Size() int
	// Return the size of the namespace
	NamespaceSize() namespace.IDSize
	// Returns if the NmtHasher ignores the max namespace.
	IsMaxNamespaceIDIgnored() bool
}
