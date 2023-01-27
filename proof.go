package nmt

import (
	"bytes"
	"hash"
	"math/bits"

	"github.com/celestiaorg/nmt/namespace"
)

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
	// leafHash are nil if the namespace is present in the NMT.
	// In case the namespace to be proved is in the min/max range of
	// the tree but absent, this will contain the leaf hash
	// necessary to verify the proof of absence.
	leafHash []byte
	// isMaxNamespaceIDIgnored is set to true if the tree from which
	// this Proof was generated from is initialized with
	// Options.IgnoreMaxNamespace == true. // TODO [Me]? not sure about the usage of this
	isMaxNamespaceIDIgnored bool
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
// of leaves of a namespace in the tree.
func (proof Proof) IsOfAbsence() bool {
	return len(proof.leafHash) > 0
}

// LeafHash returns nil if the namespace has leaves in the NMT.
// In case the namespace.ID to be proved is in the min/max range of
// the tree but absent, this will contain the leaf hash
// necessary to verify the proof of absence.
func (proof Proof) LeafHash() []byte {
	return proof.leafHash
}

// IsNonEmptyRange returns if this proof contains a valid,
// non-empty proof range.
func (proof Proof) IsNonEmptyRange() bool {
	return proof.start >= 0 && proof.start < proof.end
}

func (proof Proof) IsMaxNamespaceIDIgnored() bool {
	return proof.isMaxNamespaceIDIgnored
}

// NewEmptyRangeProof constructs a proof that proves that a namespace.ID
// does not fall within the range of an NMT.
func NewEmptyRangeProof(ignoreMaxNamespace bool) Proof {
	return Proof{0, 0, nil, nil, ignoreMaxNamespace}
}

// NewInclusionProof constructs a proof that proves that a namespace.ID
// is included in an NMT.
func NewInclusionProof(proofStart, proofEnd int, proofNodes [][]byte, ignoreMaxNamespace bool) Proof {
	return Proof{proofStart, proofEnd, proofNodes, nil, ignoreMaxNamespace}
}

// NewAbsenceProof constructs a proof that proves that a namespace.ID
// falls within the range of an NMT but no leaf with that namespace.ID is
// included.
func NewAbsenceProof(proofStart, proofEnd int, proofNodes [][]byte, leafHash []byte, ignoreMaxNamespace bool) Proof {
	return Proof{proofStart, proofEnd, proofNodes, leafHash, ignoreMaxNamespace}
}

// VerifyNamespace verifies a whole namespace, i.e. it verifies inclusion of
// the provided data in the tree. Additionally, it verifies that the namespace
// is complete and no leaf of that namespace was left out in the proof.
// leafs contain leaves within the nID
// TODO [ME] describe the parameters: proof is the range proof
func (proof Proof) VerifyNamespace(h hash.Hash, nID namespace.ID, leafs [][]byte, root []byte) bool {
	// TODO [Me] what is this check for?
	nth := NewNmtHasher(h, nID.Size(), proof.isMaxNamespaceIDIgnored)
	min := namespace.ID(MinNamespace(root, nID.Size()))
	max := namespace.ID(MaxNamespace(root, nID.Size()))
	if nID.Size() != min.Size() || nID.Size() != max.Size() {
		// conflicting namespace sizes
		return false
	}

	isEmptyRange := proof.start == proof.end
	if len(leafs) == 0 && isEmptyRange && len(proof.nodes) == 0 {
		// TODO ]Me] never saw proof.nodes been assigned in the code
		// empty proofs are always rejected unless nID is outside the range of namespaces covered by the root
		// we special case the empty root, since it purports to cover the zero namespace but does not actually
		// include any such nodes
		if nID.Less(min) || max.Less(nID) || bytes.Equal(root, nth.EmptyRoot()) {
			return true
		}
		return false
	}
	gotLeafHashes := make([][]byte, 0, len(leafs))
	nIDLen := nID.Size()
	if proof.IsOfAbsence() {
		gotLeafHashes = append(gotLeafHashes, proof.leafHash)
	} else {
		// collect leaf hashes from provided leafs and
		// do some sanity checks:
		hashLeafFunc := nth.HashLeaf
		for _, gotLeaf := range leafs {
			if len(gotLeaf) < int(nIDLen) {
				// conflicting namespace sizes
				return false
			}
			gotLeafNid := namespace.ID(gotLeaf[:nIDLen])
			if !gotLeafNid.Equal(nID) {
				// conflicting namespace IDs in leafs
				return false
			}
			leafData := append(gotLeafNid, gotLeaf[nIDLen:]...)
			gotLeafHashes = append(gotLeafHashes, hashLeafFunc(leafData))
		}
	}
	if !proof.IsOfAbsence() && len(gotLeafHashes) != (proof.End()-proof.Start()) {
		return false
	}
	// with verifyCompleteness set to true:
	return proof.verifyLeafHashes(nth, true, nID, gotLeafHashes, root)
}

func (proof Proof) verifyLeafHashes(nth *Hasher, verifyCompleteness bool, nID namespace.ID, gotLeafHashes [][]byte, root []byte) bool {
	var leafIndex uint64
	leftSubtrees := make([][]byte, 0, len(proof.nodes))

	nodes := proof.nodes
	for leafIndex != uint64(proof.Start()) && len(nodes) > 0 {
		subtreeSize := nextSubtreeSize(leafIndex, uint64(proof.Start()))
		leftSubtrees = append(leftSubtrees, nodes[0])
		nodes = nodes[1:]
		leafIndex += uint64(subtreeSize)
	}

	if verifyCompleteness {
		// leftSubtrees contains the subtree roots upto [0, r.Start)
		for _, subtree := range leftSubtrees {
			leftSubTreeMax := MaxNamespace(subtree, nth.NamespaceSize())
			if nID.LessOrEqual(namespace.ID(leftSubTreeMax)) {
				return false
			}
		}
		// rightSubtrees only contains the subtrees after [0, r.Start)
		rightSubtrees := nodes
		for _, subtree := range rightSubtrees {
			rightSubTreeMin := MinNamespace(subtree, nth.NamespaceSize())
			if namespace.ID(rightSubTreeMin).LessOrEqual(nID) {
				return false
			}
		}
	}

	var computeRoot func(start, end int) []byte
	computeRoot = func(start, end int) []byte {
		// reached a leaf
		if end-start == 1 {
			// if current range overlaps with proof range, pop and return a leaf
			if proof.start <= start && start < proof.end {
				leafHash := gotLeafHashes[0]
				gotLeafHashes = gotLeafHashes[1:]
				return leafHash
			}

			// if current range does not overlap with proof range,
			// pop and return a proof node (leaf) if present,
			// else return nil because leaf doesn't exist
			return popIfNonEmpty(&proof.nodes)
		}

		// if current range does not overlap with proof range,
		// pop and return a proof node if present,
		// else return nil because subtree doesn't exist
		if end <= proof.start || start >= proof.end {
			return popIfNonEmpty(&proof.nodes)
		}

		// Recursively get left and right subtree
		k := getSplitPoint(end - start)
		left := computeRoot(start, start+k)
		right := computeRoot(start+k, end)

		// only right leaf/subtree can be non-existent
		if right == nil {
			return left
		}
		hash := nth.HashNode(left, right)
		return hash
	}

	// estimate the leaf size of the subtree containing the proof range
	proofRangeSubtreeEstimate := getSplitPoint(proof.end) * 2
	if proofRangeSubtreeEstimate < 1 {
		proofRangeSubtreeEstimate = 1
	}
	rootHash := computeRoot(0, proofRangeSubtreeEstimate)
	for i := 0; i < len(proof.nodes); i++ {
		rootHash = nth.HashNode(rootHash, proof.nodes[i])
	}

	return bytes.Equal(rootHash, root)
}

// VerifyInclusion checks that the inclusion proof is valid by using leaf data
// and the provided proof to regenerate and compare the root. Note that the leaf
// data should not contain the prefixed namespace, unlike the tree.Push method,
// which takes prefixed data. All leaves implicitly have the same namespace ID: `nid`.
func (proof Proof) VerifyInclusion(h hash.Hash, nid namespace.ID, leaves [][]byte, root []byte) bool {
	nth := NewNmtHasher(h, nid.Size(), proof.isMaxNamespaceIDIgnored)
	hashes := make([][]byte, len(leaves))
	for i, d := range leaves {
		leafData := append(append(make([]byte, 0, len(d)+len(nid)), nid...), d...)
		hashes[i] = nth.HashLeaf(leafData)
	}

	return proof.verifyLeafHashes(nth, false, nid, hashes, root)
}

// nextSubtreeSize returns the size of the subtree adjacent to start that does
// not overlap end.
func nextSubtreeSize(start, end uint64) int {
	ideal := bits.TrailingZeros64(start)
	max := bits.Len64(end-start) - 1
	if ideal > max {
		return 1 << uint(max)
	}
	return 1 << uint(ideal)
}

// popIfNonEmpty pops the first element off of a slice only if the slice is non empty,
// else returns a nil slice
func popIfNonEmpty(s *[][]byte) []byte {
	if len(*s) != 0 {
		first := (*s)[0]
		*s = (*s)[1:]
		return first
	}
	return nil
}
