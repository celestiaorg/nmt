package internal

import (
	"bytes"
	"hash"

	"github.com/lazyledger/nmt/namespace"
)

const (
	LeafPrefix = 0
	NodePrefix = 1
)

type DefaultNmtHasher struct {
	hash.Hash
	NamespaceLen namespace.Size
}

func (n *DefaultNmtHasher) NamespaceSize() namespace.Size {
	return n.NamespaceLen
}

func NewNmtHasher(nidLen namespace.Size, baseHasher hash.Hash) *DefaultNmtHasher {
	return &DefaultNmtHasher{
		Hash:         baseHasher,
		NamespaceLen: nidLen,
	}
}

func (n *DefaultNmtHasher) EmptyRoot() namespace.IntervalDigest {
	emptyNs := bytes.Repeat([]byte{0}, int(n.NamespaceLen))

	return namespace.NewIntervalDigest(emptyNs, emptyNs, n.Sum(nil))
}

// HashLeaf hashes leaves to:
// ns(rawData) || ns(rawData) || hash(leafPrefix || rawData), where raw data is the leaf's
// data minus the namespaceID (namely leaf[NamespaceLen:]).
// Note that here minNs = maxNs = ns(leaf) = leaf[:NamespaceLen].
//nolint:errcheck
func (n *DefaultNmtHasher) HashLeaf(leaf []byte) []byte {
	h := n.Hash
	h.Reset()
	// TODO this makes assumptions on how the passed in leaf data looks like
	// instead, this should use the Data / NamespaceID methods:
	// nID := leaf.NamespaceID()
	// data := leaf.Data()
	// But this will requires further refactoring.
	// It does not matter too much right now as all this is hidden
	// in the internal package.
	nID := leaf[:n.NamespaceLen]
	data := leaf[n.NamespaceLen:]
	res := append(append(make([]byte, 0), nID...), nID...)
	h.Write([]byte{LeafPrefix})
	h.Write(data)
	return h.Sum(res)
}

// HashNode hashes inner nodes to:
// minNID || maxNID || hash(NodePrefix || left || right), where left and right are the full
// left and right child node bytes, including their respective min and max namespace IDs:
// left = left.Min() || left.Max() || l.Hash().
func (n *DefaultNmtHasher) HashNode(l, r []byte) []byte {
	h := n.Hash
	h.Reset()

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
