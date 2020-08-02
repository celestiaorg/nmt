package nmt

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/liamsi/merkletree"

	"github.com/lazyledger/nmt/internal"
	"github.com/lazyledger/nmt/namespace"
)

var (
	ErrMismatchedNamespaceSize = errors.New("mismatching namespace sizes")
	ErrInvalidPushOrder        = errors.New("pushed data has to be lexicographically ordered by namespace IDs")
)

type NamespacedMerkleTree struct {
	treeHasher Hasher
	tree       *merkletree.Tree

	// just cache stuff until we pass in a store and keep all nodes in there
	leafs      []namespace.PrefixedData
	leafHashes [][]byte
	// this can be used to efficiently lookup the range for an
	// existing namespace without iterating through the leafs
	namespaceRanges map[string]merkletree.LeafRange
	minNID          namespace.ID
	maxNID          namespace.ID
}

func New(treeHasher Hasher) *NamespacedMerkleTree {
	return &NamespacedMerkleTree{
		treeHasher: treeHasher,
		tree:       merkletree.NewFromTreehasher(treeHasher),
		// XXX: 100 seems like a good capacity for the leafs slice
		// but maybe this should also be a constructor param: for cases the caller
		// knows exactly how many leafs will be pushed this will save allocations
		// In fact, in that case the caller could pass in the whole data at once
		// and we could even use the passed in slice without allocating space for a copy.
		leafs:           make([]namespace.PrefixedData, 0, 100),
		leafHashes:      make([][]byte, 0, 100),
		namespaceRanges: make(map[string]merkletree.LeafRange),
		minNID:          bytes.Repeat([]byte{0xFF}, treeHasher.NamespaceSize()),
		maxNID:          bytes.Repeat([]byte{0x00}, treeHasher.NamespaceSize()),
	}
}

// Prove leaf at index.
// Note this is not really NMT specific but the tree supports inclusions proofs
// like any vanilla Merkle tree.
func (n NamespacedMerkleTree) Prove(index int) (Proof, error) {
	subTreeHasher := internal.NewCachedSubtreeHasher(n.leafHashes, n.treeHasher)
	// TODO: store nodes and re-use the hashes instead recomputing parts of the tree here
	proof, err := merkletree.BuildRangeProof(index, index+1, subTreeHasher)
	if err != nil {
		return NewEmptyRangeProof(), nil
	}

	return NewProofOfInclusion(index, index+1, proof), nil
}

// ProveNamespace returns a range proof for the given NamespaceID.
//
// In case the underlying tree contains leafs with the given namespace
// their start and end index will be returned together with a range proof and
// the found leaves. In that case the returned leafHashes will be nil.
//
// If the tree does not have any entries with the given Namespace ID,
// but the namespace is within the range of the tree's min and max namespace,
// this will be proven by returning the (namespaced or rather flagged)
// hashes of the leaves that would be in that range if they existed. In that
// case the returned leaves will be nil.
//
// In the case (nID < minNID) or (maxNID < nID) we do not
// generate any proof and we return an empty range (0,0) to
// indicate that this namespace is not contained in the tree.
func (n NamespacedMerkleTree) ProveNamespace(nID namespace.ID) (Proof, error) {
	// In the cases (nID < minNID) or (maxNID < nID),
	// return empty range and no proof:
	if nID.Less(n.minNID) || n.maxNID.Less(nID) {
		return NewEmptyRangeProof(), nil
	}

	found, proofStart, proofEnd := n.foundInRange(nID)
	if !found {
		// To generate a proof for an absence we calculate the
		// range the namespace would be in:
		proofStart, proofEnd = n.calculateAbsenceRange(nID)
	}
	// At this point we either found the namespace in the tree or calculated
	// the range it would be in (to generate a proof of absence and to return
	// the corresponding leaf hashes).
	subTreeHasher := internal.NewCachedSubtreeHasher(n.leafHashes, n.treeHasher)
	var err error
	proof, err := merkletree.BuildRangeProof(proofStart, proofEnd, subTreeHasher)
	if err != nil {
		// This should never happen.
		// TODO would be good to back this by more tests and fuzzing.
		return Proof{}, fmt.Errorf(
			"unexpected err: %w on nID: %v, range: [%v, %v)",
			err,
			nID,
			proofStart,
			proofEnd,
		)
	}

	if found {
		return NewProofOfInclusion(proofStart, proofEnd, proof), nil
	}
	return NewProofOfAbsence(proofStart, proofEnd, proof, n.leafHashes[proofStart:proofEnd]), nil
}

func (n NamespacedMerkleTree) calculateAbsenceRange(nID namespace.ID) (int, int) {
	foundRangeStart := false
	proofStart, proofEnd := 0, 0
	var prevLeaf namespace.PrefixedData
	for index, curLeaf := range n.leafs {
		if index == 0 {
			prevLeaf = curLeaf
			continue
		}
		prevNs := prevLeaf.NamespaceID()
		currentNs := curLeaf.NamespaceID()
		// Note that here we would also care for the case
		// current < nId < prevNs
		// but we only allow pushing leafs with ascending namespaces;
		// i.e. prevNs <= currentNs is always true.
		// Also we only check for strictly smaller: prev < nid < current
		// because if we either side was equal, we would have found the
		// namespace before.
		if prevNs.Less(nID) && nID.Less(currentNs) {
			if !foundRangeStart {
				foundRangeStart = true
				proofStart = index
			}
			proofEnd = index + 1
		}
		prevLeaf = curLeaf
	}
	return proofStart, proofEnd
}

func (n *NamespacedMerkleTree) foundInRange(nID namespace.ID) (bool, int, int) {
	// This is a faster version of this code snippet:
	// https://github.com/lazyledger/lazyledger-prototype/blob/2aeca6f55ad389b9d68034a0a7038f80a8d2982e/simpleblock.go#L106-L117
	foundRng, found := n.namespaceRanges[string(nID)]
	// XXX casting from uint64 to int is kinda crappy but nebolousLabs'
	// range proof api requires int params only to convert them to uint64 ...
	return found, int(foundRng.Start), int(foundRng.End)
}

// NamespaceSize returns the underlying namespace size. Note that
// all namespaced data is expected to have the same namespace size.
func (n NamespacedMerkleTree) NamespaceSize() int {
	return n.treeHasher.NamespaceSize()
}

// Push adds data with the corresponding namespace ID to the tree.
// Returns an error if the namespace ID size of the input
// does not match the tree's NamespaceSize() or the leafs are not pushed in
// order (i.e. lexicographically sorted by namespace ID).
func (n *NamespacedMerkleTree) Push(data namespace.PrefixedData) error {
	got, want := data.NamespaceSize(), n.NamespaceSize()
	if got != want {
		return fmt.Errorf("%w: got: %v, want: %v", ErrMismatchedNamespaceSize, got, want)
	}
	// ensure pushed data doesn't have a smaller namespace than the previous one:
	curSize := len(n.leafs)
	if curSize > 0 {
		if data.NamespaceID().Less(n.leafs[curSize-1].NamespaceID()) {
			return fmt.Errorf(
				"%w: last namespace: %v, pushed: %v",
				ErrInvalidPushOrder,
				n.leafs[curSize-1].NamespaceID(),
				data.NamespaceID(),
			)
		}
	}
	n.tree.Push(data.Bytes())
	// update relevant "caches":
	n.leafs = append(n.leafs, data)
	n.leafHashes = append(n.leafHashes, n.treeHasher.HashLeaf(data.Bytes()))
	n.updateNamespaceRanges()
	n.updateMinMaxID(data)
	return nil
}

// Return the namespaced Merkle Tree's root together with the
// min. and max. namespace ID.
func (n *NamespacedMerkleTree) Root() (
	minNs namespace.ID,
	maxNs namespace.ID,
	root []byte,
) {
	if len(n.leafs) == 0 {
		return n.treeHasher.EmptyRoot()
	}
	tRoot := n.tree.Root()
	namespaceLen := n.NamespaceSize()
	minNs = tRoot[:namespaceLen]
	maxNs = tRoot[namespaceLen : namespaceLen*2]
	root = tRoot[namespaceLen*2:]
	return
}

func (n *NamespacedMerkleTree) updateNamespaceRanges() {
	if len(n.leafs) > 0 {
		lastIndex := len(n.leafs) - 1
		lastPushed := n.leafs[lastIndex]
		lastNsStr := string(lastPushed.NamespaceID())
		lastRange, found := n.namespaceRanges[lastNsStr]
		if !found {
			n.namespaceRanges[lastNsStr] = merkletree.LeafRange{
				Start: uint64(lastIndex),
				End:   uint64(lastIndex + 1),
			}
		} else {
			n.namespaceRanges[lastNsStr] = merkletree.LeafRange{
				Start: lastRange.Start,
				End:   lastRange.End + 1,
			}
		}
	}
}

func (n *NamespacedMerkleTree) updateMinMaxID(data namespace.PrefixedData) {
	if data.NamespaceID().Less(n.minNID) {
		n.minNID = data.NamespaceID()
	}
	if n.maxNID.Less(data.NamespaceID()) {
		n.maxNID = data.NamespaceID()
	}
}
