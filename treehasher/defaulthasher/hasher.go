package defaulthasher

import (
	"bytes"
	"crypto"

	"github.com/lazyledger/nmt/treehasher"
	"github.com/lazyledger/nmt/types"
)

const (
	LeafPrefix = 0
	NodePrefix = 1
)

var _ treehasher.NmTreeHasher = &DefaultNamespacedTreeHasher{}

type DefaultNamespacedTreeHasher struct {
	crypto.Hash
	NamespaceLen int
}

func (n *DefaultNamespacedTreeHasher) NamespaceSize() int {
	return n.NamespaceLen
}

func New(nidLen int, baseHasher crypto.Hash) *DefaultNamespacedTreeHasher {
	return &DefaultNamespacedTreeHasher{
		Hash:         baseHasher,
		NamespaceLen: nidLen,
	}
}

func (n *DefaultNamespacedTreeHasher) EmptyRoot() (minNs, maxNs types.NamespaceID, root []byte) {
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
