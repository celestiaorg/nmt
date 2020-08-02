package nmt

import (
	"bytes"
	"errors"
	"math"
	"math/bits"

	"github.com/liamsi/merkletree"

	"github.com/lazyledger/nmt/namespace"
)

var (
	ErrConflictingNamespaceIDs = errors.New("conflicting namespace IDs in data")
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

// NewInclusionProof constructs a proof that proves that a namespace.ID
// is included in an NMT.
func NewInclusionProof(proofStart, proofEnd int, proofNodes [][]byte) Proof {
	return Proof{proofStart, proofEnd, proofNodes, nil}
}

// NewAbsenceProof constructs a proof that proves that a namespace.ID
// falls within the range of an NMT but no leaf with that namespace.ID is
// included.
func NewAbsenceProof(proofStart, proofEnd int, proofNodes [][]byte, leafHashes [][]byte) Proof {
	return Proof{proofStart, proofEnd, proofNodes, leafHashes}
}

// VerifyNamespace verifies TODO
func (proof Proof) VerifyNamespace(nth Hasher, nID namespace.ID, data []namespace.PrefixedData, root namespace.IntervalDigest) (bool, error) {
	// TODO add more sanity checks

	// empty range, proof and empty data: always checks out
	if len(data) == 0 && proof.start == proof.end && len(proof.nodes) == 0 {
		return true, nil
	}
	gotLeafHashes := make([][]byte, 0, len(data))
	nIDLen := nID.Size()
	if proof.IsOfAbsence() {
		gotLeafHashes = proof.leafHashes
	} else {
		// collect leaf hashes from provided data and
		// do some sanity checks:
		hashLeafFunc := nth.HashLeaf
		for _, gotLeaf := range data {
			if gotLeaf.NamespaceSize() != nIDLen {
				return false, ErrMismatchedNamespaceSize
			}
			if !gotLeaf.NamespaceID().Equal(nID) {
				return false, ErrConflictingNamespaceIDs
			}
			gotLeafHashes = append(gotLeafHashes, hashLeafFunc(gotLeaf.Bytes()))
		}
	}

	// manually build a tree using the proof hashes
	tree := merkletree.NewFromTreehasher(nth)
	var leafIndex uint64
	leftSubtrees := make([][]byte, 0, len(proof.nodes))
	consumeUntil := func(end uint64) error {
		for leafIndex != end && len(proof.nodes) > 0 {
			subtreeSize := nextSubtreeSize(leafIndex, end)
			i := bits.TrailingZeros64(uint64(subtreeSize)) // log2
			if err := tree.PushSubTree(i, proof.nodes[0]); err != nil {
				// This *probably* should never happen, but just to guard
				// against adversarial inputs, return an error instead of
				// panicking.
				return err
			}
			leftSubtrees = append(leftSubtrees, proof.nodes[0])
			proof.nodes = proof.nodes[1:]
			leafIndex += uint64(subtreeSize)
		}
		return nil
	}
	// add proof hashes from leaves [leafIndex, r.Start)
	if err := consumeUntil(uint64(proof.Start())); err != nil {
		return false, err
	}
	// add leaf hashes within the proof range
	for i := proof.Start(); i < proof.End(); i++ {
		leafHash := gotLeafHashes[0]
		gotLeafHashes = gotLeafHashes[1:]
		if err := tree.PushSubTree(0, leafHash); err != nil {
			return false, err // TODO wrap error
		}
	}
	leafIndex += uint64(proof.End() - proof.Start())

	// Prove completeness:
	rightSubtrees := proof.nodes
	for _, subtree := range leftSubtrees {
		leftSubTreeMax := namespace.IntervalDigestFromBytes(nIDLen, subtree).Max()
		if nID.LessOrEqual(leftSubTreeMax) {
			return false, nil
		}
	}
	for _, subtree := range rightSubtrees {
		rightSubTreeMin := namespace.IntervalDigestFromBytes(nIDLen, subtree).Min()
		if rightSubTreeMin.LessOrEqual(nID) {
			return false, nil
		}
	}

	// add remaining proof hashes after the last range ends
	if err := consumeUntil(math.MaxUint64); err != nil {
		return false, err
	}

	return bytes.Equal(tree.Root(), root.Bytes()), nil
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
