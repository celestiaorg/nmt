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
)

var _ merkletree.TreeHasher = &namespacedTreeHasher{}
var _ Nmt = &NamespacedMerkleTree{}

type NamespacedMerkleTree struct {
	nidLen     int
	baseHasher crypto.Hash
	tree       *merkletree.Tree
}

func (n NamespacedMerkleTree) NamespaceSize() int {
	return n.nidLen
}

func (n NamespacedMerkleTree) Push(data NamespacePrefixedData) error {
	got, want := data.NamespaceSize(), n.NamespaceSize()
	if got != want {
		return fmt.Errorf("%w: got: %v, want: %v", ErrMismatchedNamespaceSize, got, want)
	}
	// TODO: or should we only push to the actual tree at the end
	// when we compute the root? The we can push messages bundled by namespaces together: e.g. s.t.
	// they are lexicographically ordered by namespace IDs
	// (first transactions,then intermediate state roots, evidence, messages etc)
	n.tree.Push(data.Bytes())
	return nil
}

func (n NamespacedMerkleTree) Root() (minNs, maxNs NamespaceID, root []byte) {
	tRoot := n.tree.Root()
	minNs = tRoot[:n.nidLen]
	maxNs = tRoot[n.nidLen : n.nidLen*2]
	root = tRoot[n.nidLen*2:]
	return
}

func (n NamespacedMerkleTree) CompactRoot() []byte {
	h := n.baseHasher.New()
	minNs, maxNs, root := n.Root()
	h.Write(minNs)
	h.Write(maxNs)
	h.Write(root)
	// TODO: should we merkelize these 3 values instead?
	// Or add in some form of domain seperation here too?
	return h.Sum(nil)
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
func (n namespacedTreeHasher) HashLeaf(leaf []byte) []byte {
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
func (n namespacedTreeHasher) HashNode(l, r []byte) []byte {
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

	h.Write(b)
	return h.Sum(res)
}

func New(namespaceLen int, baseHasher crypto.Hash) *NamespacedMerkleTree {
	return &NamespacedMerkleTree{
		nidLen:     namespaceLen,
		baseHasher: baseHasher,
		tree:       merkletree.NewFromTreehasher(newNamespacedTreeHasher(namespaceLen, baseHasher)),
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
