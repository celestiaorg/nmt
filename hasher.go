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
	ErrUnorderedSiblings = errors.New("NMT sibling nodes should be ordered lexicographically by namespace IDs")
	ErrInvalidNodeLen    = errors.New("invalid NMT node size")
	ErrInvalidLeafLen    = errors.New("invalid NMT leaf size")
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
// Requires data of fixed size to match leaf or inner NMT nodes. Only a single
// write is allowed.
// It panics if more than one single write is attempted.
// If the data does not match the format of an NMT non-leaf node or leaf node, an error will be returned.
func (n *Hasher) Write(data []byte) (int, error) {
	if n.data != nil {
		panic("only a single Write is allowed")
	}

	ln := len(data)
	switch ln {
	// inner nodes are made up of the nmt hashes of the left and right children
	case n.Size() * 2:
		// check the format of the data
		leftChild := data[:n.Size()]
		rightChild := data[n.Size():]
		if err := n.ValidateNodes(leftChild, rightChild); err != nil {
			return 0, err
		}
		n.tp = NodePrefix
	// leaf nodes contain the namespace length and a share
	default:
		// validate the format of the leaf
		if err := n.ValidateLeaf(data); err != nil {
			return 0, err
		}
		n.tp = LeafPrefix
	}

	n.data = data
	return ln, nil
}

// Sum computes the hash. Does not append the given suffix, violating the
// interface.
// It may panic if the data being hashed is invalid. This should never happen since the Write method refuses an invalid data and errors out.
func (n *Hasher) Sum([]byte) []byte {
	switch n.tp {
	case LeafPrefix:
		res, err := n.HashLeaf(n.data)
		if err != nil {
			panic(err) // this should never happen since the data is already validated in the Write method
		}
		return res
	case NodePrefix:
		flagLen := int(n.NamespaceLen) * 2
		sha256Len := n.baseHasher.Size()
		leftChild := n.data[:flagLen+sha256Len]
		rightChild := n.data[flagLen+sha256Len:]
		res, err := n.HashNode(leftChild, rightChild)
		if err != nil {
			panic(err) // this should never happen since the data is already validated in the Write method
		}
		return res
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

// ValidateLeaf verifies if data is namespaced and returns an error if not.
func (n *Hasher) ValidateLeaf(data []byte) (err error) {
	nidSize := int(n.NamespaceSize())
	lenData := len(data)
	if lenData < nidSize {
		return fmt.Errorf("%w: got: %v, want >= %v", ErrInvalidLeafLen, lenData, nidSize)
	}
	return nil
}

// HashLeaf computes namespace hash of the namespaced data item `ndata` as
// ns(ndata) || ns(ndata) || hash(leafPrefix || ndata), where ns(ndata) is the
// namespaceID inside the data item namely leaf[:n.NamespaceLen]). Note that for
// leaves minNs = maxNs = ns(leaf) = leaf[:NamespaceLen]. HashLeaf can return the ErrInvalidNodeLen error if the input is not namespaced.
//
//nolint:errcheck
func (n *Hasher) HashLeaf(ndata []byte) ([]byte, error) {
	h := n.baseHasher
	h.Reset()

	if err := n.ValidateLeaf(ndata); err != nil {
		return nil, err
	}

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
	return nameSpacedHash, nil
}

// MustHashLeaf is a wrapper around HashLeaf that panics if an error is
// encountered. The ndata must be a valid leaf node.
func (n *Hasher) MustHashLeaf(ndata []byte) []byte {
	res, err := n.HashLeaf(ndata)
	if err != nil {
		panic(err)
	}
	return res
}

// ValidateNodeFormat checks whether the supplied node conforms to the
// namespaced hash format and returns an error if it does not. Specifically, it returns ErrInvalidNodeLen if the length of the node is less than the 2*namespace length which indicates it does not match the namespaced hash format.
func (n *Hasher) ValidateNodeFormat(node []byte) (err error) {
	totalNamespaceLen := 2 * n.NamespaceLen
	nodeLen := len(node)
	if nodeLen < int(totalNamespaceLen) {
		return fmt.Errorf("%w: got: %v, want >= %v", ErrInvalidNodeLen, nodeLen, totalNamespaceLen)
	}
	return nil
}

// validateSiblingsNamespaceOrder checks whether left and right as two sibling
// nodes in an NMT have correct namespace IDs relative to each other, more
// specifically, the maximum namespace ID of the left sibling should not exceed
// the minimum namespace ID of the right sibling. It returns ErrUnorderedSiblings error if the check fails. Note that the function assumes
// that the left and right nodes are in correct format, i.e., they are
// namespaced hash values. Otherwise, it panics.
func (n *Hasher) validateSiblingsNamespaceOrder(left, right []byte) (err error) {
	// each NMT node has two namespace IDs for the min and max
	totalNamespaceLen := 2 * n.NamespaceLen
	leftMaxNs := namespace.ID(left[n.NamespaceLen:totalNamespaceLen])
	rightMinNs := namespace.ID(right[:n.NamespaceLen])

	// check the namespace range of the left and right children
	if rightMinNs.Less(leftMaxNs) {
		return fmt.Errorf("%w: the maximum namespace of the left child %x is greater than the min namespace of the right child %x", ErrUnorderedSiblings, leftMaxNs, rightMinNs)
	}
	return nil
}

// ValidateNodes is a helper function  to verify the
// validity of the inputs of HashNode. It verifies whether left
// and right comply by the namespace hash format, and are correctly ordered
// according to their namespace IDs.
func (n *Hasher) ValidateNodes(left, right []byte) error {
	if err := n.ValidateNodeFormat(left); err != nil {
		return err
	}
	if err := n.ValidateNodeFormat(right); err != nil {
		return err
	}
	return n.validateSiblingsNamespaceOrder(left, right)
}

// HashNode calculates a namespaced hash of a node using the supplied left and
// right children. The input values, `left` and `right,` are namespaced hash
// values with the format `minNID || maxNID || hash.`
// The HashNode function returns an error if the provided inputs are invalid. Specifically, it returns the ErrInvalidNodeLen error if the left and right inputs are not in the namespaced hash format,
// and the ErrUnorderedSiblings error if left.maxNID is greater than right.minNID.
// By default, the normal namespace hash calculation is
// followed, which is `res = min(left.minNID, right.minNID) || max(left.maxNID,
// right.maxNID) || H(NodePrefix, left, right)`. `res` refers to the return
// value of the HashNode. However, if the `ignoreMaxNs` property of the Hasher
// is set to true, the calculation of the namespace ID range of the node
// slightly changes. In this case, when setting the upper range, the maximum
// possible namespace ID (i.e., 2^NamespaceIDSize-1) should be ignored if
// possible. This is achieved by taking the maximum value among only those namespace
// IDs available in the range of its left and right children that are not
// equal to the maximum possible namespace ID value. If all the namespace IDs are equal
// to the maximum possible value, then the maximum possible value is used.
func (n *Hasher) HashNode(left, right []byte) ([]byte, error) {
	if err := n.ValidateNodeFormat(left); err != nil {
		return nil, err
	}
	if err := n.ValidateNodeFormat(right); err != nil {
		return nil, err
	}

	// check the namespace range of the left and right children
	if err := n.validateSiblingsNamespaceOrder(left, right); err != nil {
		return nil, err
	}
	h := n.baseHasher
	h.Reset()

	// the actual hash result of the children got extended (or flagged) by their
	// children's minNs || maxNs; hence the flagLen = 2 * NamespaceLen:
	flagLen := 2 * n.NamespaceLen
	leftMinNs, leftMaxNs := left[:n.NamespaceLen], left[n.NamespaceLen:flagLen]
	rightMinNs, rightMaxNs := right[:n.NamespaceLen], right[n.NamespaceLen:flagLen]

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
	return h.Sum(res), nil
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
