package nmt

type NamespaceID []byte

type Nmt interface {
	// NamespaceSize returns the underlying namespace size. Note that
	// all namespaced data is expected to have the same namespace size.
	NamespaceSize() int
	// Push adds data with the corresponding namespace ID to the tree.
	// Should return an error if the namespace ID size of the input
	// does not match the tree's NamespaceSize().
	Push(data NamespacePrefixedData) error

	// Return the namespaced Merkle Tree's root together with the
	// min. and max. namespace ID.
	Root() (minNs, maxNS NamespaceID, root []byte)
}
