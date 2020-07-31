package nmt

type TreeHasher interface {
	// EmptyRoot returns the namespaced root for a no-leafs Namespaced Merkle tree.
	EmptyRoot() (minNs, maxNs NamespaceID, root []byte)

	// HashLeaf defines how a leaf is hashed.
	HashLeaf(leaf []byte) []byte

	// HashNode defines how a inner node is hashed.
	HashNode(l, r []byte) []byte

	// Size returns the size of the underlying hasher.
	Size() int
}
