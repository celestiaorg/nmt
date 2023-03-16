package nmt

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"math/bits"

	"github.com/celestiaorg/nmt/namespace"
)

var ErrFailedCompletenessCheck = errors.New("failed completeness check")

// Proof represents a namespace proof of a namespace.ID in an NMT. In case this
// proof proves the absence of a namespace.ID in a tree it also contains the
// leaf hashes of the range where that namespace would be.
type Proof struct {
	// start index of the leaves that match the queried namespace.ID.
	start int
	// end index (non-inclusive) of the leaves that match the queried
	// namespace.ID.
	end int
	// nodes hold the tree nodes necessary for the Merkle range proof of
	// `[start, end)` in the order of an in-order traversal of the tree. in
	// specific, nodes contain: 1) the namespaced hash of the left siblings for
	// the Merkle inclusion proof of the `start` leaf 2) the namespaced hash of
	// the right siblings of the Merkle inclusion proof of  the `end` leaf
	nodes [][]byte
	// leafHash are nil if the namespace is present in the NMT. In case the
	// namespace to be proved is in the min/max range of the tree but absent,
	// this will contain the leaf hash necessary to verify the proof of absence.
	// leafHash contains a tree leaf that 1) its namespace ID is the smallest
	// namespace ID larger than nid and 2) the namespace ID of the leaf to the
	// left of it is smaller than the nid.
	leafHash []byte
	// isMaxNamespaceIDIgnored is set to true if the tree from which this Proof
	// was generated from is initialized with Options.IgnoreMaxNamespace ==
	// true. The IgnoreMaxNamespace flag influences the calculation of the
	// namespace ID range for intermediate nodes in the tree. This flag signals
	// that, when determining the upper limit of the namespace ID range for a
	// tree node, the maximum possible namespace ID (equivalent to
	// "NamespaceIDSize" bytes of 0xFF, or 2^NamespaceIDSize-1) should be
	// omitted if feasible. For a more in-depth understanding of this field,
	// refer to the "HashNode" method in the "Hasher.
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

// Nodes return the proof nodes that together with the corresponding leaf values
// can be used to recompute the root and verify this proof.
func (proof Proof) Nodes() [][]byte {
	return proof.nodes
}

// IsOfAbsence returns true if this proof proves the absence of leaves of a
// namespace in the tree.
func (proof Proof) IsOfAbsence() bool {
	return len(proof.leafHash) > 0
}

// LeafHash returns nil if the namespace has leaves in the NMT. In case the
// namespace.ID to be proved is in the min/max range of the tree but absent,
// this will contain the leaf hash necessary to verify the proof of absence.
func (proof Proof) LeafHash() []byte {
	return proof.leafHash
}

// IsNonEmptyRange returns true if this proof contains a valid, non-empty proof
// range.
func (proof Proof) IsNonEmptyRange() bool {
	return proof.start >= 0 && proof.start < proof.end
}

func (proof Proof) IsMaxNamespaceIDIgnored() bool {
	return proof.isMaxNamespaceIDIgnored
}

// NewEmptyRangeProof constructs a proof that proves that a namespace.ID does
// not fall within the range of an NMT.
func NewEmptyRangeProof(ignoreMaxNamespace bool) Proof {
	return Proof{0, 0, nil, nil, ignoreMaxNamespace}
}

// NewInclusionProof constructs a proof that proves that a namespace.ID is
// included in an NMT.
func NewInclusionProof(proofStart, proofEnd int, proofNodes [][]byte, ignoreMaxNamespace bool) Proof {
	return Proof{proofStart, proofEnd, proofNodes, nil, ignoreMaxNamespace}
}

// NewAbsenceProof constructs a proof that proves that a namespace.ID falls
// within the range of an NMT but no leaf with that namespace.ID is included.
func NewAbsenceProof(proofStart, proofEnd int, proofNodes [][]byte, leafHash []byte, ignoreMaxNamespace bool) Proof {
	return Proof{proofStart, proofEnd, proofNodes, leafHash, ignoreMaxNamespace}
}

// VerifyNamespace verifies a whole namespace, i.e. 1) it verifies inclusion of
// the provided `data` in the tree (or the proof.leafHash in case of absence
// proof) 2) it verifies that the namespace is complete i.e., the data items
// matching the namespace ID `nID`  are within the range [`proof.start`,
// `proof.end`) and no data of that namespace was left out. VerifyNamespace
// deems an empty `proof` valid if the queried `nID` falls outside the namespace
// range of the supplied `root` or if the `root` is empty
//
// `h` MUST be the same as the underlying hash function used to generate the
// proof. Otherwise, the verification will fail. `nID` is the namespace ID for
// which the namespace `proof` is generated. `data` contains the namespaced data
// items (but not namespace hash)  underlying the leaves of the tree in the
// range of [`proof.start`, `proof.end`). For an absence `proof`, the `data` is
// empty. `data` items MUST be ordered according to their index in the tree,
// with `data[0]` corresponding to the namespaced data at index `start`,
//
//	and the last element in `data` corresponding to the data item at index
//	`end-1` of the tree.
//
// `root` is the root of the NMT against which the `proof` is verified.
func (proof Proof) VerifyNamespace(h hash.Hash, nID namespace.ID, data [][]byte, root []byte) bool {
	nth := NewNmtHasher(h, nID.Size(), proof.isMaxNamespaceIDIgnored)
	min := namespace.ID(MinNamespace(root, nID.Size()))
	max := namespace.ID(MaxNamespace(root, nID.Size()))
	if nID.Size() != min.Size() || nID.Size() != max.Size() {
		// conflicting namespace sizes
		return false
	}

	isEmptyRange := proof.start == proof.end
	if len(data) == 0 && isEmptyRange && len(proof.nodes) == 0 {
		// empty proofs are always rejected unless nID is outside the range of
		// namespaces covered by the root we special case the empty root, since
		// it purports to cover the zero namespace but does not actually include
		// any such nodes
		if nID.Less(min) || max.Less(nID) || bytes.Equal(root, nth.EmptyRoot()) {
			return true
		}
		return false
	}
	gotLeafHashes := make([][]byte, 0, len(data))
	nIDLen := nID.Size()
	if proof.IsOfAbsence() {
		gotLeafHashes = append(gotLeafHashes, proof.leafHash)
		// conduct some sanity checks:
		leafMinNID := namespace.ID(proof.leafHash[:nIDLen])
		if !nID.Less(leafMinNID) {
			// leafHash.minNID  must be greater than nID
			return false
		}

	} else {
		// collect leaf hashes from provided data and do some sanity checks:
		hashLeafFunc := nth.HashLeaf
		for _, gotLeaf := range data {
			if nth.ValidateLeaf(gotLeaf) != nil {
				return false
			}
			// check whether the namespace ID of the data matches the queried nID
			if gotLeafNid := namespace.ID(gotLeaf[:nIDLen]); !gotLeafNid.Equal(nID) {
				// conflicting namespace IDs in data
				return false
			}
			// hash the leaf data
			leafHash, err := hashLeafFunc(gotLeaf)
			if err != nil { // this can never happen due to the initial validation of the leaf at the beginning of the loop
				return false
			}
			gotLeafHashes = append(gotLeafHashes, leafHash)
		}
	}
	// check whether the number of leaves match the proof range i.e., end-start.
	// If not, make an early return.
	if !proof.IsOfAbsence() && len(gotLeafHashes) != (proof.End()-proof.Start()) {
		return false
	}
	// with verifyCompleteness set to true:
	res, err := proof.verifyLeafHashes(nth, true, nID, gotLeafHashes, root)
	if err != nil {
		return false
	}
	return res
}

// The verifyLeafHashes function checks whether the given proof is a valid Merkle
// range proof for the leaves in the leafHashes input.
// The leafHashes parameter is a list of leaf hashes, where each leaf hash is represented
// by a byte slice.
// If the verifyCompleteness parameter is set to true, the function also checks
// the completeness of the proof by verifying that there is no leaf in the
// tree represented by the root parameter that matches the namespace ID nID
// but is not present in the leafHashes list.
// verifyLeafHashes returns  verified=true if the proof is valid, false otherwise.
// In verified=false, the value of proofFailureCause indicates the cause of the unsuccessful proof verification.
func (proof Proof) verifyLeafHashes(nth *Hasher, verifyCompleteness bool, nID namespace.ID, leafHashes [][]byte, root []byte) (verified bool, proofFailureCause error) {
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
				return false, ErrFailedCompletenessCheck
			}
		}
		for _, subtree := range rightSubtrees {
			rightSubTreeMin := MinNamespace(subtree, nth.NamespaceSize())
			if namespace.ID(rightSubTreeMin).LessOrEqual(nID) {
				return false, ErrFailedCompletenessCheck
			}
		}
	}

	var computeRoot func(start, end int) ([]byte, error)
	// computeRoot can return error iff the HashNode function fails while calculating the root
	computeRoot = func(start, end int) ([]byte, error) {
		// reached a leaf
		if end-start == 1 {
			// if the leaf index falls within the proof range, pop and return a
			// leaf
			if proof.start <= start && start < proof.end {
				leafHash := leafHashes[0]
				// advance leafHashes
				leafHashes = leafHashes[1:]
				return leafHash, nil
			}

			// if the leaf index  is outside the proof range, pop and return a
			// proof node (which in this case is a leaf) if present, else return
			// nil because leaf doesn't exist
			return popIfNonEmpty(&proof.nodes), nil
		}

		// if current range does not overlap with the proof range, pop and
		// return a proof node if present, else return nil because subtree
		// doesn't exist
		if end <= proof.start || start >= proof.end {
			return popIfNonEmpty(&proof.nodes), nil
		}

		// Recursively get left and right subtree
		k := getSplitPoint(end - start)
		left, err := computeRoot(start, start+k)
		if err != nil {
			return nil, fmt.Errorf("failed to compute subtree root [%d, %d): %w", start, start+k, err)
		}
		right, err := computeRoot(start+k, end)
		if err != nil {
			return nil, fmt.Errorf("failed to compute subtree root [%d, %d): %w", start+k, end, err)
		}

		// only right leaf/subtree can be non-existent
		if right == nil {
			return left, nil
		}
		hash, err := nth.HashNode(left, right)
		if err != nil {
			return nil, fmt.Errorf("failed to hash node: %w", err)
		}
		return hash, nil
	}

	// estimate the leaf size of the subtree containing the proof range
	proofRangeSubtreeEstimate := getSplitPoint(proof.end) * 2
	if proofRangeSubtreeEstimate < 1 {
		proofRangeSubtreeEstimate = 1
	}
	rootHash, err := computeRoot(0, proofRangeSubtreeEstimate)
	if err != nil {
		return false, fmt.Errorf("failed to compute root [%d, %d): %w", 0, proofRangeSubtreeEstimate, err)
	}
	for i := 0; i < len(proof.nodes); i++ {
		rootHash, err = nth.HashNode(rootHash, proof.nodes[i])
		if err != nil {
			return false, fmt.Errorf("failed to hash node: %w", err)
		}
	}

	return bytes.Equal(rootHash, root), nil
}

// VerifyInclusion checks that the inclusion proof is valid by using leaf data
// and the provided proof to regenerate and compare the root. Note that the leaf
// data should not contain the prefixed namespace, unlike the tree.Push method,
// which takes prefixed data. All leaves implicitly have the same namespace ID:
// `nid`.
func (proof Proof) VerifyInclusion(h hash.Hash, nid namespace.ID, leaves [][]byte, root []byte) bool {
	nth := NewNmtHasher(h, nid.Size(), proof.isMaxNamespaceIDIgnored)
	hashes := make([][]byte, len(leaves))
	for i, d := range leaves {
		leafData := append(
			append(make([]byte, 0, len(d)+len(nid)), nid...), d...,
		)
		res, err := nth.HashLeaf(leafData)
		if err != nil {
			return false
		}
		hashes[i] = res
	}

	res, err := proof.verifyLeafHashes(nth, false, nid, hashes, root)
	if err != nil {
		return false
	}
	return res
}

// nextSubtreeSize returns the number of leaves of the subtree adjacent to start
// that does not overlap end.
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

// popIfNonEmpty pops the first element off of a slice only if the slice is
// non-empty, else returns a nil slice
func popIfNonEmpty(s *[][]byte) []byte {
	if len(*s) != 0 {
		first := (*s)[0]
		*s = (*s)[1:]
		return first
	}
	return nil
}
