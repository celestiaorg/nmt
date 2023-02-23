package nmt

import (
	"bytes"
	"errors"
	"fmt"
	"hash"

	"github.com/celestiaorg/nmt/namespace"
)

const (
	LeafPrefix = 0
	NodePrefix = 1
)

var _ hash.Hash = (*Hasher)(nil)

var (
	ErrInvalidNamespaceRange = errors.New("min namespace ID is greater than max namespace ID for NMT node")
	ErrUnorderedSiblings     = errors.New("NMT sibling nodes should be ordered lexicographically by namespace IDs")
)

type Hasher struct {
	baseHasher   hash.Hash
	NamespaceLen namespace.IDSize

	// The "ignoreMaxNs" flag influences the calculation of the namespace ID
	// range for intermediate nodes in the tree i.e., HashNode method. This flag
	// signals that, when determining the upper limit of the namespace ID range
	// for a tree node, the maximum possible namespace ID (equivalent to
	// "NamespaceLen" bytes of 0xFF, or 2^NamespaceLen-1) should be omitted if
	// feasible. For a more in-depth understanding of this field, refer to the
	// "HashNode".
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
// Requires data of fixed size to match leaf or inner NMT nodes,
// otherwise, returns error. Only a single write is allowed.
func (n *Hasher) Write(data []byte) (int, error) {
	if n.data != nil {
		panic("only a single Write is allowed")
	}

	if _, err := n.validateNodeFormat(data); err != nil {
		return 0, err
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

// Sum computes the hash. Does not append the given suffix, violating the
// interface.
func (n *Hasher) Sum([]byte) []byte {
	switch n.tp {
	case LeafPrefix:
		return n.HashLeaf(n.data)
	case NodePrefix:
		flagLen := int(n.NamespaceLen) * 2
		sha256Len := n.baseHasher.Size()
		leftChild := n.data[:flagLen+sha256Len]
		rightChild := n.data[flagLen+sha256Len:]
		return n.HashNode(leftChild, rightChild)
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

func (n *Hasher) ValidateNamespacedData(data []byte) (bool, error) {
	nidSize := int(n.NamespaceSize())
	if len(data) < nidSize {
		return false, fmt.Errorf("%w: got: %v, want >= %v", ErrMismatchedNamespaceSize, len(data), nidSize)
	}
	return true, nil
}

// HashLeaf computes namespace hash of the namespaced data item `ndata` to:
// the namespaced hash has the following format: ns(ndata) || ns(ndata) || hash(leafPrefix || ndata), where ns(ndata) is the namespaceID
// inside the data item namely leaf[:n.NamespaceLen]).
// Note that for leaves minNs = maxNs = ns(leaf) = leaf[:NamespaceLen].
// HashLeaf can panic if the input is not properly namespaced.
// to avoid panic, call ValidateNamespacedData on the input data `ndata` before calling HashLeaf.
//
//nolint:errcheck
func (n *Hasher) HashLeaf(ndata []byte) []byte {
	h := n.baseHasher
	h.Reset()

	nID := ndata[:n.NamespaceLen]
	resLen := int(2*n.NamespaceLen) + n.baseHasher.Size()
	minMaxNIDs := make([]byte, 0, resLen)
	minMaxNIDs = append(minMaxNIDs, nID...) // nID
	minMaxNIDs = append(minMaxNIDs, nID...) // nID || nID

	// add LeafPrefix to the ndata
	leafPrefixedNData := make([]byte, 0, len(ndata)+1)
	leafPrefixedNData = append(leafPrefixedNData, LeafPrefix)
	leafPrefixedNData = append(leafPrefixedNData, ndata...)
	h.Write(leafPrefixedNData)

	// compute h(LeafPrefix || ndata) and append it to the minMaxNIDs
	nameSpacedHash := h.Sum(minMaxNIDs) // nID || nID || h(LeafPrefix || ndata)
	return nameSpacedHash
}

// validateNodeFormat checks whether the supplied node conforms to the namespaced hash format.
// the function returns true if the node is in correct format, otherwise false alongside with an error.
func (n *Hasher) validateNodeFormat(node []byte) (validated bool, err error) {
	totalNameSpaceLen := 2 * n.NamespaceLen
	if len(node) < int(totalNameSpaceLen) {
		return false, fmt.Errorf("%w: got: %v, want >= %v", ErrMismatchedNamespaceSize, len(node), totalNameSpaceLen)
	}
	minND := namespace.ID(MinNamespace(node, n.NamespaceLen))
	maxND := namespace.ID(MaxNamespace(node, n.NamespaceLen))
	if maxND.Less(minND) {
		return false, fmt.Errorf("%w: min namespace ID %x > max namespace ID %x", ErrInvalidNamespaceRange, minND, maxND)
	}
	return true, nil
}

// validateNamespaceOrder checks whether left and right as two sibling nodes in an NMT have correct namespace IDs relative to each other, more specifically,
// the maximum namespace ID of the left sibling should not exceed the minimum namespace ID of the right sibling.
// the function returns true if the condition holds, otherwise false alongside with an error.
func (n *Hasher) validateNamespaceOrder(left, right []byte) (verified bool, err error) {
	// the actual hash result of the children got extended (or flagged) by their
	// children's minNs || maxNs; hence the flagLen = 2 * NamespaceLen:
	totalNameSpaceLen := 2 * n.NamespaceLen
	leftMaxNs := namespace.ID(left[n.NamespaceLen:totalNameSpaceLen])
	rightMinNs := namespace.ID(right[:n.NamespaceLen])

	// check the namespace range of the left and right children
	if rightMinNs.Less(leftMaxNs) {
		return false, fmt.Errorf("%w: the maximum namespace of the left child %x is greater than the min namespace of the right child %x", ErrUnorderedSiblings, leftMaxNs, rightMinNs)
	}
	return true, nil
}

// ValidateNodes is helper function to be called prior to HashNode to verify the validity of the inputs of HashNode and avoid panics.
// It verifies whether left and right comply by the namespace hash format, and are correctly ordered according to their namespace IDs.
func (n *Hasher) ValidateNodes(left, right []byte) (bool, error) {
	if _, err := n.validateNodeFormat(left); err != nil {
		return false, err
	}
	if _, err := n.validateNodeFormat(right); err != nil {
		return false, err
	}
	if _, err := n.validateNamespaceOrder(left, right); err != nil {
		return false, err
	}
	return true, nil
}

// HashNode calculates a namespaced hash of a node using the supplied left and
// right children. The input values, "left" and "right," are namespaced hash
// values with the format "minNID || maxNID || hash." The HashNode function may
// panic if the inputs provided are invalid, i.e., when left and right are not
// in the namespaced hash format or when left.maxNID is greater than
// right.minNID. To prevent panicking, call ValidateNodes(left, right) to check these criteria
// before calling the HashNode function. By default, the normal namespace hash
// calculation is followed, which is "res = min(left.minNID, right.minNID) ||
// max(left.maxNID, right.maxNID) || H(NodePrefix, left, right)". "res" refers
// to the return value of the HashNode. However, if the "ignoreMaxNs" property
// of the Hasher is set to true, the calculation of the namespace ID range of
// the node slightly changes. In this case, when setting the upper range, the
// maximum possible namespace ID (i.e., 2^NamespaceIDSize-1) should be ignored
// if possible. This is achieved by taking the maximum value among the namespace
// IDs available in the range of its left and right children (i.e.,
// max(left.minNID, left.maxNID , right.minNID, right.maxNID)), which is not
// equal to the maximum possible namespace ID value. If such a namespace ID does
// not exist, the maximum NID is calculated as normal, i.e., "res.maxNID =
// max(left.maxNID , right.maxNID).
func (n *Hasher) HashNode(left, right []byte) []byte {
	h := n.baseHasher
	h.Reset()

	// the actual hash result of the children got extended (or flagged) by their
	// children's minNs || maxNs; hence the flagLen = 2 * NamespaceLen:
	flagLen := 2 * n.NamespaceLen
	leftMinNs, leftMaxNs := left[:n.NamespaceLen], left[n.NamespaceLen:flagLen]
	rightMinNs, rightMaxNs := right[:n.NamespaceLen], right[n.NamespaceLen:flagLen]

	// check the namespace range of the left and right children
	rightMinNID := namespace.ID(rightMinNs)
	leftMaxNID := namespace.ID(leftMaxNs)
	if rightMinNID.Less(leftMaxNID) {
		panic("nodes are out of order: the maximum namespace of the left child is greater than the min namespace of the right child")
	}

	minNs := min(leftMinNs, rightMinNs)
	var maxNs []byte
	if n.ignoreMaxNs && n.precomputedMaxNs.Equal(leftMinNs) {
		maxNs = n.precomputedMaxNs
	} else if n.ignoreMaxNs && n.precomputedMaxNs.Equal(rightMinNs) {
		maxNs = leftMaxNs
	} else {
		maxNs = max(leftMaxNs, rightMaxNs)
	}

	res := make([]byte, 0)
	res = append(res, minNs...)
	res = append(res, maxNs...)

	// Note this seems a little faster than calling several Write()s on the
	// underlying Hash function (see:
	// https://github.com/google/trillian/pull/1503):
	data := make([]byte, 0, 1+len(left)+len(right))
	data = append(data, NodePrefix)
	data = append(data, left...)
	data = append(data, right...)
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
