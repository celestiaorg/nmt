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
	// Options.IgnoreMaxNamespace == true.
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
func (proof Proof) VerifyNamespace(h hash.Hash, nID namespace.ID, data [][]byte, root []byte) bool {
	nth := NewNmtHasher(h, nID.Size(), proof.isMaxNamespaceIDIgnored)
	min := namespace.ID(MinNamespace(root, nID.Size()))
	max := namespace.ID(MaxNamespace(root, nID.Size()))
	if nID.Size() != min.Size() || nID.Size() != max.Size() {
		// conflicting namespace sizes
		return false
	}

	isEmptyRange := proof.start == proof.end
	// empty range, proof, and data: always checks out
	if len(data) == 0 && isEmptyRange && len(proof.nodes) == 0 {
		return true
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
	consumeUntil := func(end uint64) {
		for leafIndex != end && len(proof.nodes) > 0 {
			subtreeSize := nextSubtreeSize(leafIndex, end)
			// i := bits.TrailingZeros64(uint64(subtreeSize))
			leftSubtrees = append(leftSubtrees, proof.nodes[0])
			proof.nodes = proof.nodes[1:]
			leafIndex += uint64(subtreeSize)
		}
	}
	// add proof hashes from leaves [leafIndex, r.Start)
	consumeUntil(uint64(proof.Start()))

	leafIndex += uint64(proof.End() - proof.Start())

	rightSubtrees := proof.nodes
	// Verify completeness (in case of single leaf proofs we do not need do these checks):
	if verifyCompleteness {
		// leftSubtrees contains the subtree roots upto [0, r.Start)
		for _, subtree := range leftSubtrees {
			leftSubTreeMax := MaxNamespace(subtree, nth.NamespaceSize())
			if nID.LessOrEqual(namespace.ID(leftSubTreeMax)) {
				return false
			}
		}
		// rightSubtrees only contains the subtrees after [0, r.Start)
		for _, subtree := range rightSubtrees {
			rightSubTreeMin := MinNamespace(subtree, nth.NamespaceSize())
			if namespace.ID(rightSubTreeMin).LessOrEqual(nID) {
				return false
			}
		}
	}

	start := 0
	end := proof.end - proof.start
	rootHash := computeRoot(start, end, nth, gotLeafHashes)

	subTreeHeight := bits.TrailingZeros64(uint64(start))
	subTreeIndex := proof.start
	for i := 0; i < subTreeHeight; i++ {
		subTreeIndex /= 2
	}

	heightLeft := len(leftSubtrees) + len(rightSubtrees)
	for heightLeft != 0 {
		if subTreeIndex%2 == 1 {
			if len(leftSubtrees) == 0 {
				return false
			}
			index := len(leftSubtrees) - 1
			rootHash = nth.HashNode(leftSubtrees[index], rootHash)
			leftSubtrees = leftSubtrees[:index]
		} else {
			if len(rightSubtrees) == 0 {
				return false
			}
			rootHash = nth.HashNode(rootHash, rightSubtrees[0])
			leftSubtrees = rightSubtrees[1:]
		}
		heightLeft--
	}

	return bytes.Equal(rootHash, root)
}

func computeRoot(start, end int, nth *Hasher, leafHashes [][]byte) []byte {
	switch end - start {
	case 0:
		rootHash := nth.EmptyRoot()
		return rootHash
	case 1:
		leafHash := leafHashes[start]
		return leafHash
	default:
		k := getSplitPoint(end - start)
		left := computeRoot(start, start+k, nth, leafHashes)
		right := computeRoot(start+k, end, nth, leafHashes)
		hash := nth.HashNode(left, right)
		return hash
	}
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
