package nmt

import (
	"bytes"
	"hash"
	"math/bits"

	"github.com/celestiaorg/nmt/namespace"
)

// Proof represents a namespace proof of a namespace.ID in an NMT.
// In case this proof proves the absence of a namespace.ID
// in a tree it also contains the leaf hashes of the range
// where that namespace would be.
type Proof struct {
	// start index of the leaves that match the queried namespace.ID.
	start int
	// end index (non-inclusive) of the leaves that match the queried namespace.ID.
	end int
	// nodes hold the tree nodes necessary for the Merkle range proof of `[start, end)` in the order of an in-order traversal of the tree.
	// in specific, nodes contain: 1) the namespaced hash of the left siblings for the Merkle inclusion proof of the `start` leaf
	// 2) the namespaced hash of the right siblings of the Merkle inclusion proof of  the `end` leaf
	nodes [][]byte
	// leafHash are nil if the namespace is present in the NMT.
	// In case the namespace to be proved is in the min/max range of
	// the tree but absent, this will contain the leaf hash
	// necessary to verify the proof of absence.
	// leafHash contains a tree leaf that 1) its namespace ID is the largest namespace ID less than nid and 2) the child to the left of it is smaller than the nid 3) the child to the right of it is larger than nid.
	leafHash []byte
	// isMaxNamespaceIDIgnored is set to true if the tree from which
	// this Proof was generated from is initialized with
	// Options.IgnoreMaxNamespace == true.
	isMaxNamespaceIDIgnored bool
}

// Start index of this proof.
func (proof Proof) Start() int {
	return proof.start
}

// End index of this proof, non-inclusive.
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

// IsNonEmptyRange returns true if this proof contains a valid,
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
func NewInclusionProof(
	proofStart, proofEnd int, proofNodes [][]byte, ignoreMaxNamespace bool
) Proof {
	return Proof{proofStart, proofEnd, proofNodes, nil, ignoreMaxNamespace}
}

// NewAbsenceProof constructs a proof that proves that a namespace.ID
// falls within the range of an NMT but no leaf with that namespace.ID is
// included.
func NewAbsenceProof(
	proofStart, proofEnd int, proofNodes [][]byte, leafHash []byte,
	ignoreMaxNamespace bool
) Proof {
	return Proof{proofStart, proofEnd, proofNodes, leafHash, ignoreMaxNamespace}
}

// VerifyNamespace verifies a whole namespace, i.e. 1) it verifies inclusion of
// the provided `data` in the tree (or the `proof.leafHash` in case of absence proof) 2) it verifies that the namespace
// is complete i.e., the data items matching the namespace ID `nID`  are within the range [`proof.start`, `proof.end`)
// hence no data of that namespace was left out in the `proof`.
// VerifyNamespace deems an empty `proof` valid if the queried `nID` falls outside the namespace range of the supplied `root` or if the `root` is empty
//
// `h` MUST be the same as the underlying hash function used to generate the proof. Otherwise, the verification will fail.
// `nID` is the namespace ID for which the namespace `proof` is generated.
// `data` contains the namespaced data (but not namespace hash) underlying the leaves of the tree in the range of [`proof.start`, `proof.end`). For an absence `proof`, the `data` is empty.
//
// `data` items MUST be ordered according to their index in the tree, with `data[0]` corresponding to the namespaced data at index `start`,
//
//	and the last element in `data` corresponding to the data item at index `end-1` of the tree.
//
// `root` is the root of the NMT against which the `proof` is verified.
func (proof Proof) VerifyNamespace(
	h hash.Hash, nID namespace.ID, data [][]byte, root []byte
) bool {
	nth := NewNmtHasher(h, nID.Size(), proof.isMaxNamespaceIDIgnored)
	min := namespace.ID(MinNamespace(root, nID.Size()))
	max := namespace.ID(MaxNamespace(root, nID.Size()))
	if nID.Size() != min.Size() || nID.Size() != max.Size() {
		// conflicting namespace sizes
		return false
	}

	isEmptyRange := proof.start == proof.end
	if len(data) == 0 && isEmptyRange && len(proof.nodes) == 0 {
		// empty proofs are always rejected unless nID is outside the range of namespaces covered by the root
		// we special case the empty root, since it purports to cover the zero namespace but does not actually
		// include any such nodes
		if nID.Less(min) || max.Less(nID) || bytes.Equal(
			root, nth.EmptyRoot()
		) {
			return true
		}
		return false
	}
	gotLeafHashes := make([][]byte, 0, len(data))
	nIDLen := nID.Size()
	if proof.IsOfAbsence() {
		gotLeafHashes = append(gotLeafHashes, proof.leafHash)
	} else {
		// collect leaf hashes from provided data and
		// do some sanity checks:
		hashLeafFunc := nth.HashLeaf
		for _, gotLeaf := range data {
			if len(gotLeaf) < int(nIDLen) {
				// conflicting namespace sizes
				return false
			}
			gotLeafNid := namespace.ID(gotLeaf[:nIDLen])
			if !gotLeafNid.Equal(nID) {
				// conflicting namespace IDs in data
				return false
			}
			leafData := append(
				gotLeafNid, gotLeaf[nIDLen:]...
			)
			// hash the leaf data
			gotLeafHashes = append(gotLeafHashes, hashLeafFunc(leafData))
		}
	}
	// check whether the number of data match the proof range end-start and make an early return if not
	if !proof.IsOfAbsence() && len(gotLeafHashes) != (proof.End()-proof.Start()) {
		return false
	}
	// with verifyCompleteness set to true:
	return proof.verifyLeafHashes(nth, true, nID, gotLeafHashes, root)
}

// verifyLeafHashes checks whether all the leaves matching the namespace ID nID are covered by the proof if verifyCompleteness is set to true
func (proof Proof) verifyLeafHashes(
	nth *Hasher, verifyCompleteness bool, nID namespace.ID, leafHashes [][]byte,
	root []byte
) bool {
	var leafIndex uint64
	// leftSubtrees is to be populated by the subtree roots upto [0, r.Start)
	leftSubtrees := make([][]byte, 0, len(proof.nodes))

	nodes := proof.nodes
	for leafIndex != uint64(proof.Start()) && len(nodes) > 0 {
		subtreeSize := nextSubtreeSize(leafIndex, uint64(proof.Start()))
		leftSubtrees = append(leftSubtrees, nodes[0])
		nodes = nodes[1:]
		leafIndex += uint64(subtreeSize)
	}
	// rightSubtrees only contains the subtrees after r.End
	rightSubtrees := nodes

	if verifyCompleteness {
		// leftSubtrees contains the subtree roots upto [0, r.Start)
		for _, subtree := range leftSubtrees {
			leftSubTreeMax := MaxNamespace(subtree, nth.NamespaceSize())
			if nID.LessOrEqual(namespace.ID(leftSubTreeMax)) {
				return false
			}
		}
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
			// if the leaf index falls within the proof range, pop and return a leaf
			if proof.start <= start && start < proof.end {
				leafHash := leafHashes[0]
				// advance leafHashes
				leafHashes = leafHashes[1:]
				return leafHash
			}

			// if current range does not overlap with the proof range,
			// pop and return a proof node (which in this case is a leaf) if present,
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
func (proof Proof) VerifyInclusion(
	h hash.Hash, nid namespace.ID, leaves [][]byte, root []byte
) bool {
	nth := NewNmtHasher(h, nid.Size(), proof.isMaxNamespaceIDIgnored)
	hashes := make([][]byte, len(leaves))
	for i, d := range leaves {
		leafData := append(
			append(make([]byte, 0, len(d)+len(nid)), nid...), d...
		)
		hashes[i] = nth.HashLeaf(leafData)
	}

	return proof.verifyLeafHashes(nth, false, nid, hashes, root)
}

// nextSubtreeSize returns the number of leaves of the subtree adjacent to start that does
// not overlap end.
func nextSubtreeSize(start, end uint64) int {
	// the highest left subtree
	ideal := bits.TrailingZeros64(start)
	// number of bits required to represent end-start
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