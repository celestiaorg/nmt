package nmt

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

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

var _ merkletree.TreeHasher = &namespacedTreeHasher{}
var _ Nmt = &NamespacedMerkleTree{}

type NamespacedMerkleTree struct {
	nidLen     int
	baseHasher crypto.Hash
	leafs      []NamespacePrefixedData
	tree       *merkletree.Tree
}

func (n NamespacedMerkleTree) NamespaceSize() int {
	return n.nidLen
}

func (n *NamespacedMerkleTree) Push(data NamespacePrefixedData) error {
	got, want := data.NamespaceSize(), n.NamespaceSize()
	if got != want {
		return fmt.Errorf("%w: got: %v, want: %v", ErrMismatchedNamespaceSize, got, want)
	}
	// ensure pushed data doesn't have a smaller namespace than the previous one:
	curSize := len(n.leafs)
	if curSize > 0 {
		if bytes.Compare(data.NamespaceID(), n.leafs[curSize-1].NamespaceID()) < 0 {
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
	return nil
}

func (n *NamespacedMerkleTree) Root() (minNs, maxNs NamespaceID, root []byte) {
	tRoot := n.tree.Root()
	minNs = tRoot[:n.nidLen]
	maxNs = tRoot[n.nidLen : n.nidLen*2]
	root = tRoot[n.nidLen*2:]
	return
}

type namespacedTreeHasher struct {
	crypto.Hash
	NamespaceLen int
}

func newNamespacedTreeHasher(nidLen int, baseHasher crypto.Hash) *namespacedTreeHasher {
	return &namespacedTreeHasher{
		Hash:         baseHasher,
		NamespaceLen: nidLen,
	}
}

// HashLeaf hashes leafs to:
// ns(rawData) || ns(rawData) || hash(leafPrefix || rawData), where raw data is the leaf's
// data minus the namespaceID (namely leaf[NamespaceLen:]).
// Note that here minNs = maxNs = ns(leaf) = leaf[:NamespaceLen].
//nolint:errcheck
func (n *namespacedTreeHasher) HashLeaf(leaf []byte) []byte {
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
func (n *namespacedTreeHasher) HashNode(l, r []byte) []byte {
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
		nidLen:     namespaceLen,
		baseHasher: baseHasher,
		// XXX: 100 seems like a good capacity for the leafs slice
		// but maybe this should also be a constructor param: for cases the caller
		// knows exactly how many leafs will be pushed this will save allocations
		// In fact, in that case the caller could pass in the whole data at once
		// and we could even use the passed in slice without allocating space for a copy.
		leafs: make([]NamespacePrefixedData, 0, 100),
		tree:  merkletree.NewFromTreehasher(newNamespacedTreeHasher(namespaceLen, baseHasher)),
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
