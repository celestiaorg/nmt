package nmt

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/lazyledger/nmt/internal"

	"github.com/liamsi/merkletree"
)

const (
	LeafPrefix = 0
	NodePrefix = 1
)

var (
	ErrMismatchedNamespaceSize = errors.New("mismatching namespace sizes")
	ErrInvalidPushOrder        = errors.New("pushed data has to be lexicographically order by namespaces")
)

var _ TreeHasher = &DefaultNamespacedTreeHasher{}

type NamespacedMerkleTree struct {
	namespaceLen int
	treeHasher   TreeHasher
	tree         *merkletree.Tree

	// just cache stuff until we pass in a store and keep all nodes in there
	leafs      []NamespacePrefixedData
	leafHashes [][]byte
	// this can be used to efficiently lookup the range for an
	// existing namespace without iterating through the leafs
	namespaceRanges map[string]merkletree.LeafRange
}

// Prove leaf at index.
// Note this is not really NMT specific but the tree supports inclusions proofs
// like any vanilla Merkle tree.
func (n NamespacedMerkleTree) Prove(index int) (
	proof [][]byte,
	proofIdx int,
	totalNumLeafs int,
	err error, // TODO: we can probably get rid of the error here too
) {
	subTreeHasher := internal.NewCachedSubtreeHasher(n.leafHashes, n.treeHasher)
	proofIdx = index
	totalNumLeafs = len(n.leafs)
	// TODO: store nodes and re-use the hashes instead recomputing parts of the tree here
	proof, err = merkletree.BuildRangeProof(index, index+1, subTreeHasher)

	return
}

// ProveNamespace returns some kind of range proof for the given NamespaceID.
// In case the underlying tree contains leafs with the given namespace
// their start and end index will be returned together with a range proof and the found leafs.
// In the above case the leafHashes will be nil.
// If the tree does not have any entries with the given NamespaceID,
// but the will be proven by returning the (namespaced or rather flagged)
// hashes of the leafs that would be in the range if they existed.
// Either foundLeafs or leafHashes should be nil.
// Note that in cases (nID < minNID) or (maxNID < nID) we do not
// generate any proof and we return an empty range (0,0) to
// indicate that this namespace is not contained in the tree.
func (n NamespacedMerkleTree) ProveNamespace(nID NamespaceID) (
	proofStart int,
	proofEnd int,
	proof [][]byte,
	foundLeafs []NamespacePrefixedData,
	leafHashes [][]byte, // XXX: introduce a type/type alias, e.g FlaggedHas
) {
	found, proofStart, proofEnd := n.foundNamespaceID(nID)

	// If we did not find the namespace, that either means that there is a gap in the tree
	// i.e. a range where this namespace would live if it was pushed,
	// or, it is smaller or greater than any pushed namespace.
	// XXX this can probably be simplified, too:
	foundRangeStart := false
	if !found {
		// Generate a proof for an absence using the
		// range the namespace would be in
		// TODO: document this as a proper godoc comment
		var prevLeaf NamespacePrefixedData
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
	}
	if found || foundRangeStart {
		subTreeHasher := internal.NewCachedSubtreeHasher(n.leafHashes, n.treeHasher)
		var err error
		proof, err = merkletree.BuildRangeProof(proofStart, proofEnd, subTreeHasher)
		if err != nil {
			// This should never happen.
			// TODO would be good to back this by more tests and fuzzing.
			panic(fmt.Sprintf(
				"unexpected err: %v on nID: %v, range: [%v, %v)",
				err,
				nID,
				proofStart,
				proofEnd,
			))
		}
	}
	proofMessages := n.leafs[proofStart:proofEnd]
	if found {
		return proofStart, proofEnd, proof, proofMessages, nil
	}
	// Note that in cases (nID < minNID) or (maxNID < nID) we do not generate any
	// proof. Also we return an empty range (0,0) to indicate that this namespace is
	// *not* contained in the tree.
	return proofStart, proofEnd, proof, nil, n.leafHashes[proofStart:proofEnd]
}

func (n *NamespacedMerkleTree) foundNamespaceID(nID NamespaceID) (bool, int, int) {
	foundRng, found := n.namespaceRanges[string(nID)]
	// XXX casting from uint64 to int is kinda crappy but nebolousLabs'
	// range proof api requires int params only to convert them to uint64 ...
	return found, int(foundRng.Start), int(foundRng.End)
}

// NamespaceSize returns the underlying namespace size. Note that
// all namespaced data is expected to have the same namespace size.
func (n NamespacedMerkleTree) NamespaceSize() int {
	return n.namespaceLen
}

// Push adds data with the corresponding namespace ID to the tree.
// Returns an error if the namespace ID size of the input
// does not match the tree's NamespaceSize() or the leafs are not pushed in
// order (i.e. lexicographically sorted by namespace ID).
func (n *NamespacedMerkleTree) Push(data NamespacePrefixedData) error {
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
	n.leafs = append(n.leafs, data)
	n.leafHashes = append(n.leafHashes, n.treeHasher.HashLeaf(data.Bytes()))
	n.updateNamespaceRanges()
	return nil
}

// Return the namespaced Merkle Tree's root together with the
// min. and max. namespace ID.
func (n *NamespacedMerkleTree) Root() (
	minNs NamespaceID,
	maxNs NamespaceID,
	root []byte,
) {
	if len(n.leafs) == 0 {
		return n.treeHasher.EmptyRoot()
	}
	tRoot := n.tree.Root()
	minNs = tRoot[:n.namespaceLen]
	maxNs = tRoot[n.namespaceLen : n.namespaceLen*2]
	root = tRoot[n.namespaceLen*2:]
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

type DefaultNamespacedTreeHasher struct {
	crypto.Hash
	NamespaceLen int
}

func NewDefaultNamespacedTreeHasher(nidLen int, baseHasher crypto.Hash) *DefaultNamespacedTreeHasher {
	return &DefaultNamespacedTreeHasher{
		Hash:         baseHasher,
		NamespaceLen: nidLen,
	}
}

func (n *DefaultNamespacedTreeHasher) EmptyRoot() (minNs, maxNs NamespaceID, root []byte) {
	emptyNs := bytes.Repeat([]byte{0}, n.NamespaceLen)
	placeHolderHash := bytes.Repeat([]byte{0}, n.Size())
	return emptyNs, emptyNs, placeHolderHash
}

// HashLeaf hashes leafs to:
// ns(rawData) || ns(rawData) || hash(leafPrefix || rawData), where raw data is the leaf's
// data minus the namespaceID (namely leaf[NamespaceLen:]).
// Note that here minNs = maxNs = ns(leaf) = leaf[:NamespaceLen].
//nolint:errcheck
func (n *DefaultNamespacedTreeHasher) HashLeaf(leaf []byte) []byte {
	h := n.New()

	nID := leaf[:n.NamespaceLen]
	data := leaf[n.NamespaceLen:]
	res := append(append(make([]byte, 0), nID...), nID...)
	h.Write([]byte{LeafPrefix})
	h.Write(data)
	return h.Sum(res)
}

// HashNode hashes inner nodes to:
// minNID || maxNID || hash(NodePrefix || left || right), where left and right are the full
// left and right child node bytes (including their respective min and max namespace IDs).
func (n *DefaultNamespacedTreeHasher) HashNode(l, r []byte) []byte {
	h := n.New()
	// the actual hash result of the children got extended (or flagged) by their
	// children's minNs || maxNs; hence the flagLen = 2 * NamespaceLen:
	flagLen := 2 * n.NamespaceLen
	leftMinNs, leftMaxNs := l[:n.NamespaceLen], l[n.NamespaceLen:flagLen]
	rightMinNs, rightMaxNs := r[:n.NamespaceLen], r[n.NamespaceLen:flagLen]

	minNs := min(leftMinNs, rightMinNs)
	maxNs := max(leftMaxNs, rightMaxNs)
	res := append(append(make([]byte, 0), minNs...), maxNs...)

	// Note this seems a little faster than calling several Write()s on the
	// underlying Hash function (see: https://github.com/google/trillian/pull/1503):
	b := append(append(append(
		make([]byte, 0, 1+len(l)+len(r)),
		NodePrefix),
		l...),
		r...)
	//nolint:errcheck
	h.Write(b)
	return h.Sum(res)
}

func New(namespaceLen int, baseHasher crypto.Hash) *NamespacedMerkleTree {
	return &NamespacedMerkleTree{
		namespaceLen: namespaceLen,
		treeHasher:   NewDefaultNamespacedTreeHasher(namespaceLen, baseHasher),
		// XXX: 100 seems like a good capacity for the leafs slice
		// but maybe this should also be a constructor param: for cases the caller
		// knows exactly how many leafs will be pushed this will save allocations
		// In fact, in that case the caller could pass in the whole data at once
		// and we could even use the passed in slice without allocating space for a copy.
		leafs:           make([]NamespacePrefixedData, 0, 100),
		leafHashes:      make([][]byte, 0, 100),
		namespaceRanges: make(map[string]merkletree.LeafRange),
		tree:            merkletree.NewFromTreehasher(NewDefaultNamespacedTreeHasher(namespaceLen, baseHasher)),
	}
}

func max(ns []byte, ns2 []byte) []byte {
	if bytes.Compare(ns, ns2) >= 0 {
		return ns
	}
	return ns2
}

func min(ns []byte, ns2 []byte) []byte {
	if bytes.Compare(ns, ns2) <= 0 {
		return ns
	}
	return ns2
}
