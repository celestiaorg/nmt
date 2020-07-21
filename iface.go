package nmt

type NamespaceID []byte

type NamespacedData interface {
	NamespaceID() NamespaceID
	Data() []byte
}

type Nmt interface {
	// Push adds data with the corresponding namespace ID to the tree.
	Push(data NamespacedData)
	// PushBatch adds a batch of namespaced data.
	//
	// Corresponds to several calls of Push() but can be
	// optimized for one-shot trees  that just take all the input
	// data and compute the root once.
	PushBatch(data ...NamespacedData)

	// Return the namespaced Merkle Tree's root together with the
	// min. and max. namespace ID.
	Root() (minNs, maxNS NamespaceID, root []byte)
}
