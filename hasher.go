package nmt

import (
	"bytes"
	"crypto/sha256"
	"hash"

	"github.com/lazyledger/nmt/namespace"
)

const (
	LeafPrefix = 0
	NodePrefix = 1

	DefaultNamespaceIDLen = 8
)

// defaultHasher uses sha256 as a base-hasher, 8 bytes
// for the namespace IDs and ignores the maximum possible namespace.
var defaultHasher = NewNmtHasher(sha256.New(), DefaultNamespaceIDLen, true)

// Sha256Namespace8FlaggedLeaf uses sha256 as a base-hasher, 8 bytes
// for the namespace IDs and ignores the maximum possible namespace.
//
// Sha256Namespace8FlaggedLeaf(namespacedData) results in:
// ns(rawData) || ns(rawData) || sha256(LeafPrefix || rawData),
// where rawData is the leaf's data minus the namespace.ID prefix
// (namely namespacedData[NamespaceLen:]).
//
// Note that different from other cryptographic hash functions, this here
// makes assumptions on the input:
// len(namespacedData) >= DefaultNamespaceIDLen has to hold,
// as the first DefaultNamespaceIDLen bytes are interpreted as the namespace ID).
// If the input does not fulfil this, we will panic.
// The output will be of length 2*DefaultNamespaceIDLen+sha256.Size = 48 bytes.
func Sha256Namespace8FlaggedLeaf(namespacedData []byte) []byte {
	return defaultHasher.HashLeaf(namespacedData)
}

// Sha256Namespace8FlaggedInner hashes inner nodes to:
// minNID || maxNID || sha256(NodePrefix || leftRight), where leftRight consists of the full
// left and right child node bytes, including their respective min and max namespace IDs.
// Hence, the input has to be of size:
// 48 = 32 + 8 + 8  = sha256.Size + 2*DefaultNamespaceIDLen bytes.
// If the input does not fulfil this, we will panic.
// The output will also be of length 2*DefaultNamespaceIDLen+sha256.Size = 48 bytes.
func Sha256Namespace8FlaggedInner(leftRight []byte) []byte {
	const flagLen = DefaultNamespaceIDLen * 2
	sha256Len := defaultHasher.Size()
	left := leftRight[:flagLen+sha256Len]
	right := leftRight[flagLen+sha256Len:]

	return defaultHasher.HashNode(left, right)
}

type Hasher struct {
	hash.Hash
	NamespaceLen namespace.IDSize

	ignoreMaxNs      bool
	precomputedMaxNs namespace.ID
}

func (n *Hasher) IsMaxNamespaceIDIgnored() bool {
	return n.ignoreMaxNs
}

func (n *Hasher) NamespaceSize() namespace.IDSize {
	return n.NamespaceLen
}

func NewNmtHasher(baseHasher hash.Hash, nidLen namespace.IDSize, ignoreMaxNamespace bool) *Hasher {
	return &Hasher{
		Hash:             baseHasher,
		NamespaceLen:     nidLen,
		ignoreMaxNs:      ignoreMaxNamespace,
		precomputedMaxNs: bytes.Repeat([]byte{0xFF}, int(nidLen)),
	}
}

func (n *Hasher) EmptyRoot() []byte {
	emptyNs := bytes.Repeat([]byte{0}, int(n.NamespaceLen))
	h := n.Sum(nil)
	digest := append(append(emptyNs, emptyNs...), h...)

	return digest
}

// HashLeaf hashes leaves to:
// ns(rawData) || ns(rawData) || hash(leafPrefix || rawData), where raw data is the leaf's
// data minus the namespaceID (namely leaf[NamespaceLen:]).
// Hence, the input length has to be greater or equal to the
// size of the underlying namespace.ID.
//
//Note that for leaves minNs = maxNs = ns(leaf) = leaf[:NamespaceLen].
//nolint:errcheck
func (n *Hasher) HashLeaf(leaf []byte) []byte {
	h := n.Hash
	h.Reset()

	nID := leaf[:n.NamespaceLen]
	data := leaf[n.NamespaceLen:]
	res := append(append(make([]byte, 0), nID...), nID...)
	data = append([]byte{LeafPrefix}, data...)
	h.Write(data)
	return h.Sum(res)
}

// HashNode hashes inner nodes to:
// minNID || maxNID || hash(NodePrefix || left || right), where left and right are the full
// left and right child node bytes, including their respective min and max namespace IDs:
// left = left.Min() || left.Max() || l.Hash().
func (n *Hasher) HashNode(l, r []byte) []byte {
	h := n.Hash
	h.Reset()

	// the actual hash result of the children got extended (or flagged) by their
	// children's minNs || maxNs; hence the flagLen = 2 * NamespaceLen:
	flagLen := 2 * n.NamespaceLen
	leftMinNs, leftMaxNs := l[:n.NamespaceLen], l[n.NamespaceLen:flagLen]
	rightMinNs, rightMaxNs := r[:n.NamespaceLen], r[n.NamespaceLen:flagLen]

	minNs := min(leftMinNs, rightMinNs)
	var maxNs []byte
	if n.ignoreMaxNs && n.precomputedMaxNs.Equal(leftMinNs) {
		maxNs = n.precomputedMaxNs
	} else if n.ignoreMaxNs && n.precomputedMaxNs.Equal(rightMinNs) {
		maxNs = leftMaxNs
	} else {
		maxNs = max(leftMaxNs, rightMaxNs)
	}

	res := append(append(make([]byte, 0), minNs...), maxNs...)

	// Note this seems a little faster than calling several Write()s on the
	// underlying Hash function (see: https://github.com/google/trillian/pull/1503):
	data := append(append(append(
		make([]byte, 0, 1+len(l)+len(r)),
		NodePrefix),
		l...),
		r...)
	//nolint:errcheck
	h.Write(data)
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
