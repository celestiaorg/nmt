package nmt

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

type NamespacedProver interface {
	// Prove leaf at index.
	// Note this is not really NMT specific (XXX the min/maxNs is stripped off the root)
	// but the tree supports inclusions proves like any vanilla Merkle tree.
	Prove(index int) (rawRoot []byte, rawProof [][]byte, proofIdx int, totalNumLeafs int, err error)
	// ProveNamespace returns some kind of range proof for the given NamspaceID.
	// In case the underlying tree contains leafs with the given namespace they will be returned.
	// If the tree does not have any entries with the given NamespaceID,
	// this will be proven by returning the (namespaced or rather flagged)
	// hashes of the leafs that would be in the range if they existed.
	// Either foundLeafs or leafHashes should be nil.
	ProveNamespace(nID NamespaceID) (
		proofStart int,
		proofEnd int,
		proof [][]byte,
		foundLeafs []NamespacePrefixedData,
		leafHashes [][]byte, // XXX: introduce a type/type alias, e.g FlaggedHash
	)
}
