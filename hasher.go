package nmt

import (
	"bytes"
	"crypto/sha256"
	"hash"

	"github.com/celestiaorg/nmt/namespace"
)

const (
	LeafPrefix = 0
	NodePrefix = 1
)

var _ hash.Hash = (*Hasher)(nil)

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
	sha256Len := defaultHasher.baseHasher.Size()
	left := leftRight[:flagLen+sha256Len]
	right := leftRight[flagLen+sha256Len:]

	return defaultHasher.HashNode(left, right)
}

type Hasher struct {
	baseHasher   hash.Hash
	NamespaceLen namespace.IDSize

	ignoreMaxNs      bool
	precomputedMaxNs namespace.ID

	tp   byte   // keeps type of NMT node to be hashed
	data []byte // written data of the NMT node
}

func (n *Hasher) IsMaxNamespaceIDIgnored() bool {
	return n.ignoreMaxNs
}

func (n *Hasher) NamespaceSize() namespace.IDSize {
	return n.NamespaceLen
}

func NewNmtHasher(baseHasher hash.Hash, nidLen namespace.IDSize, ignoreMaxNamespace bool) *Hasher {
	return &Hasher{
		baseHasher:       baseHasher,
		NamespaceLen:     nidLen,
		ignoreMaxNs:      ignoreMaxNamespace,
		precomputedMaxNs: bytes.Repeat([]byte{0xFF}, int(nidLen)),
	}
}

// Size returns the number of bytes Sum will return.
func (n *Hasher) Size() int {
	return n.baseHasher.Size() + int(n.NamespaceLen)*2
}

// Write writes the namespaced data to be hashed.
//
// Requires data of fixed size to match leaf or inner NMT nodes.
// Only a single write is allowed.
func (n *Hasher) Write(data []byte) (int, error) {
	if n.data != nil {
		panic("only a single Write is allowed")
	}

	ln := len(data)
	switch ln {
	// inner nodes are made up of the nmt hashes of the left and right children
	case n.Size() * 2:
		n.tp = NodePrefix
	// leaf nodes contain the namespace length and a share
	default:
		n.tp = LeafPrefix
	}

	n.data = data
	return ln, nil
}

// Sum computes the hash.
// Does not append the given suffix, violating the interface.
func (n *Hasher) Sum([]byte) []byte {
	switch n.tp {
	case LeafPrefix:
		return n.HashLeaf(n.data)
	case NodePrefix:
		flagLen := int(n.NamespaceLen) * 2
		sha256Len := n.Size()
		return n.HashNode(n.data[:flagLen+sha256Len], n.data[flagLen+sha256Len:])
	default:
		panic("nmt node type wasn't set")
	}
}

// Reset resets the Hash to its initial state.
func (n *Hasher) Reset() {
	n.tp, n.data = 255, nil // reset with an invalid node type, as zero value is a valid Leaf
	n.baseHasher.Reset()
}

// BlockSize returns the hash's underlying block size.
func (n *Hasher) BlockSize() int {
	return n.baseHasher.BlockSize()
}

func (n *Hasher) EmptyRoot() []byte {
	emptyNs := bytes.Repeat([]byte{0}, int(n.NamespaceLen))
	h := n.baseHasher.Sum(nil)
	digest := append(append(emptyNs, emptyNs...), h...)

	return digest
}

// HashLeaf hashes leaves to:
// ns(rawData) || ns(rawData) || hash(leafPrefix || rawData), where raw data is the leaf's
// data minus the namespaceID (namely leaf[NamespaceLen:]).
// Hence, the input length has to be greater or equal to the
// size of the underlying namespace.ID.
//
// Note that for leaves minNs = maxNs = ns(leaf) = leaf[:NamespaceLen].
//
//nolint:errcheck
func (n *Hasher) HashLeaf(leaf []byte) []byte {
	h := n.baseHasher
	h.Reset()

	nID := leaf[:n.NamespaceLen]
	resLen := int(2*n.NamespaceLen) + n.baseHasher.Size()
	res := append(append(make([]byte, 0, resLen), nID...), nID...)
	// h(0x00, d.namespaceID, d.rawData)
	data := append(append(make([]byte, 0, len(leaf)+1), LeafPrefix), leaf...)
	h.Write(data)
	return h.Sum(res)
}

// HashNode hashes inner nodes to:
// minNID || maxNID || hash(NodePrefix || left || right), where left and right are the full
// left and right child node bytes, including their respective min and max namespace IDs:
// left = left.Min() || left.Max() || l.Hash().
func (n *Hasher) HashNode(l, r []byte) []byte {
	h := n.baseHasher
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
