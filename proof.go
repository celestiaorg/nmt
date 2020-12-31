package nmt

import (
	"bytes"
	"hash"
	"math"
	"math/bits"

	"github.com/lazyledger/merkletree"

	"github.com/lazyledger/nmt/internal"
	"github.com/lazyledger/nmt/namespace"
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
func (proof Proof) VerifyNamespace(h hash.Hash, nID namespace.ID, data [][]byte, root namespace.IntervalDigest) bool {
	nth := internal.NewNmtHasher(h, nID.Size(), proof.isMaxNamespaceIDIgnored)
	if nID.Size() != root.Min().Size() || nID.Size() != root.Max().Size() {
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

func (proof Proof) verifyLeafHashes(nth internal.NmtHasher, verifyCompleteness bool, nID namespace.ID, gotLeafHashes [][]byte, root namespace.IntervalDigest) bool {
	// The code below is almost identical to NebulousLabs'
	// merkletree.VerifyMultiRangeProof.
	//
	// We copy and modify it here for two reasons:
	// - we have the leaf hashes at hand and don't want to construct a merkletree.LeafHasher
	// - we can now check completeness directly after iterating
	//   the leaf hashes within the proof range without looping
	//   through the sub-trees again
	// orig: https://gitlab.com/NebulousLabs/merkletree/-/blob/master/range.go#L363-417

	// manually build a tree using the proof hashes
	tree := merkletree.NewFromTreehasher(nth)
	var leafIndex uint64
	leftSubtrees := make([][]byte, 0, len(proof.nodes))
	consumeUntil := func(end uint64) {
		for leafIndex != end && len(proof.nodes) > 0 {
			subtreeSize := nextSubtreeSize(leafIndex, end)
			i := bits.TrailingZeros64(uint64(subtreeSize)) // log2
			// Note: we do never push the subtrees out of order
			// and we do not use the proofIndex. Hence,
			// tree.PushSubTree can not fail here:
			//nolint:errcheck
			tree.PushSubTree(i, proof.nodes[0])
			leftSubtrees = append(leftSubtrees, proof.nodes[0])
			proof.nodes = proof.nodes[1:]
			leafIndex += uint64(subtreeSize)
		}
	}
	// add proof hashes from leaves [leafIndex, r.Start)
	consumeUntil(uint64(proof.Start()))
	// add leaf hashes within the proof range
	for i := proof.Start(); i < proof.End(); i++ {
		leafHash := gotLeafHashes[0]
		gotLeafHashes = gotLeafHashes[1:]
		// tree.PushSubTree can not fail here for same reasons
		// as in consumeUntil:
		//nolint:errcheck
		tree.PushSubTree(0, leafHash)
	}
	leafIndex += uint64(proof.End() - proof.Start())

	// Verify completeness (in case of single leaf proofs we do not need do these checks):
	if verifyCompleteness {
		// leftSubtrees contains the subtree roots upto [0, r.Start)
		for _, subtree := range leftSubtrees {
			leftSubTreeMax := namespace.IntervalDigestFromBytes(nth.NamespaceSize(), subtree).Max()
			if nID.LessOrEqual(leftSubTreeMax) {
				return false
			}
		}
		// rightSubtrees only contains the subtrees after [0, r.Start)
		rightSubtrees := proof.nodes
		for _, subtree := range rightSubtrees {
			rightSubTreeMin := namespace.IntervalDigestFromBytes(nth.NamespaceSize(), subtree).Min()
			if rightSubTreeMin.LessOrEqual(nID) {
				return false
			}
		}
	}

	// add remaining proof hashes after the last range ends
	consumeUntil(math.MaxUint64)

	return bytes.Equal(tree.Root(), root.Bytes())
}

func (proof Proof) VerifyInclusion(h hash.Hash, nid namespace.ID, data []byte, root namespace.IntervalDigest) bool {
	nth := internal.NewNmtHasher(h, nid.Size(), proof.isMaxNamespaceIDIgnored)
	leafData := append(nid, data...)
	return proof.verifyLeafHashes(nth, false, nid, [][]byte{nth.HashLeaf(leafData)}, root)
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
