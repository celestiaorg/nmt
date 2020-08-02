package nmt

// Proof represents proof of a namespace.ID in an NMT.
// In case this proof proves the absence of a namespace.ID
// in a tree it also contains the leaf hashes of the range
// where that namespace would be.
type Proof struct {
	// start index of this proof.
	start int
	// end index of this proof.
	end int
	// Nodes that together with the corresponding leaf values
	// can be used to recompute the root and verify this proof.
	nodes [][]byte
	// leafHashes are nil if the namespace is present in the NMT.
	// In case the namespace to be proved is in the min/max range of
	// the tree but absent, this will contain the leaf hashes
	// necessary to verify the proof of absence.
	leafHashes [][]byte
}

// Start index of this proof.
func (proof Proof) Start() int {
	return proof.start
}

// End index of this proof.
func (proof Proof) End() int {
	return proof.end
}

// Nodes return the proof nodes that together with the
// corresponding leaf values can be used to recompute the
// root and verify this proof.
func (proof Proof) Nodes() [][]byte {
	return proof.nodes
}

// IsOfAbsence returns true if this proof proves the absence
// of a namespace in the tree.
func (proof Proof) IsOfAbsence() bool {
	return len(proof.leafHashes) > 0
}

// LeafHashes returns nil if the namespace has leaves in the NMT.
// In case the namespace.ID to be proved is in the min/max range of
// the tree but absent, this will contain the leaf hashes
// necessary to verify the proof of absence.
func (proof Proof) LeafHashes() [][]byte {
	return proof.leafHashes
}

// IsNonEmptyRange returns if this proof contains a valid,
// non-empty proof range.
func (proof Proof) IsNonEmptyRange() bool {
	return proof.start >= 0 && proof.start < proof.end
}

// NewEmptyRangeProof constructs a proof that proves that a namespace.ID
// does not fall within the range of an NMT.
func NewEmptyRangeProof() Proof {
	return Proof{0, 0, nil, nil}
}

// NewProofOfInclusion constructs a proof that proves that a namespace.ID
// is included in an NMT.
func NewProofOfInclusion(proofStart, proofEnd int, proofNodes [][]byte) Proof {
	return Proof{proofStart, proofEnd, proofNodes, nil}
}

// NewProofOfAbsence constructs a proof that proves that a namespace.ID
// falls within the range of an NMT but no leaf with that namespace.ID is
// included.
func NewProofOfAbsence(proofStart, proofEnd int, proofNodes [][]byte, leafHashes [][]byte) Proof {
	return Proof{proofStart, proofEnd, proofNodes, leafHashes}
}
