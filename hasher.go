package nmt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"github.com/celestiaorg/nmt/namespace"
)

const (
	LeafPrefix = 0
	NodePrefix = 1
)

var (
	nodePrefixBytes = []byte{NodePrefix}
	leafPrefixBytes = []byte{LeafPrefix}
)

var _ hash.Hash = (*NmtHasher)(nil)

var (
	ErrUnorderedSiblings         = errors.New("NMT sibling nodes should be ordered lexicographically by namespace IDs")
	ErrInvalidNodeLen            = errors.New("invalid NMT node size")
	ErrInvalidLeafLen            = errors.New("invalid NMT leaf size")
	ErrInvalidNodeNamespaceOrder = errors.New("invalid NMT node namespace order")
)

// Hasher describes the interface nmts use to hash leafs and nodes.
//
// Note: it is not advised to create alternative hashers if following the
// specification is desired. The main reason this exists is to not follow the
// specification for testing purposes.
type Hasher interface {
	IsMaxNamespaceIDIgnored() bool
	NamespaceSize() namespace.IDSize
	HashLeaf(data []byte) ([]byte, error)
	HashNode(leftChild, rightChild []byte) ([]byte, error)
	EmptyRoot() []byte
}

type ExtendedHasher interface {
	Hasher
	HashLeafWithBuffer(data []byte, buffer []byte) ([]byte, error)
	HashNodeReuse(leftChild, rightChild []byte) ([]byte, error)
}

var _ Hasher = &NmtHasher{}

// NmtHasher is the default hasher. It follows the description of the original
// hashing function described in the LazyLedger white paper.
type NmtHasher struct { //nolint:revive
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

func (n *NmtHasher) IsMaxNamespaceIDIgnored() bool {
	return n.ignoreMaxNs
}

func (n *NmtHasher) NamespaceSize() namespace.IDSize {
	return n.NamespaceLen
}

func NewNmtHasher(baseHasher hash.Hash, nidLen namespace.IDSize, ignoreMaxNamespace bool) *NmtHasher {
	return &NmtHasher{
		baseHasher:       baseHasher,
		NamespaceLen:     nidLen,
		ignoreMaxNs:      ignoreMaxNamespace,
		precomputedMaxNs: bytes.Repeat([]byte{0xFF}, int(nidLen)),
	}
}

// Size returns the number of bytes Sum will return.
func (n *NmtHasher) Size() int {
	return n.baseHasher.Size() + int(n.NamespaceLen)*2
}

// Write writes the namespaced data to be hashed.
//
// Requires data of fixed size to match leaf or inner NMT nodes. Only a single
// write is allowed.
// It panics if more than one single write is attempted.
// If the data does not match the format of an NMT non-leaf node or leaf node, an error will be returned.
func (n *NmtHasher) Write(data []byte) (int, error) {
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
func (n *NmtHasher) Sum([]byte) []byte {
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
func (n *NmtHasher) Reset() {
	n.tp, n.data = 255, nil // reset with an invalid node type, as zero value is a valid Leaf
	n.baseHasher.Reset()
}

// BlockSize returns the hash's underlying block size.
func (n *NmtHasher) BlockSize() int {
	return n.baseHasher.BlockSize()
}

func (n *NmtHasher) EmptyRoot() []byte {
	n.baseHasher.Reset()
	// make returns a zeroed slice, exactly what we need for the (nID || nID)
	zeroSize := int(n.NamespaceLen) * 2
	fullSize := zeroSize + n.baseHasher.Size()

	digest := make([]byte, zeroSize, fullSize)
	return n.baseHasher.Sum(digest)
}

// ValidateLeaf verifies if data is namespaced and returns an error if not.
func (n *NmtHasher) ValidateLeaf(data []byte) (err error) {
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
func (n *NmtHasher) HashLeaf(ndata []byte) ([]byte, error) {
	return n.HashLeafWithBuffer(ndata, nil)
}

// HashLeafWithBuffer computes namespace hash using a provided buffer to reduce allocations.
// If buffer is nil or has insufficient capacity, a new buffer is allocated.
func (n *NmtHasher) HashLeafWithBuffer(ndata []byte, buffer []byte) ([]byte, error) {
	h := n.baseHasher
	h.Reset()

	if err := n.ValidateLeaf(ndata); err != nil {
		return nil, err
	}

	nID := ndata[:n.NamespaceLen]
	resLen := int(2*n.NamespaceLen) + n.baseHasher.Size()

	var minMaxNIDs []byte
	if cap(buffer) >= resLen {
		minMaxNIDs = buffer[:0]
	} else {
		minMaxNIDs = make([]byte, 0, resLen)
	}

	minMaxNIDs = append(minMaxNIDs, nID...) // nID
	minMaxNIDs = append(minMaxNIDs, nID...) // nID || nID

	h.Write(leafPrefixBytes)
	h.Write(ndata)

	// compute h(LeafPrefix || ndata) and append it to the minMaxNIDs
	nameSpacedHash := h.Sum(minMaxNIDs) // nID || nID || h(LeafPrefix || ndata)
	return nameSpacedHash, nil
}

// MustHashLeaf is a wrapper around HashLeaf that panics if an error is
// encountered. The ndata must be a valid leaf node.
func (n *NmtHasher) MustHashLeaf(ndata []byte) []byte {
	res, err := n.HashLeaf(ndata)
	if err != nil {
		panic(err)
	}
	return res
}

// nsIDRange represents the range of namespace IDs with minimum and maximum values.
type nsIDRange struct {
	Min, Max namespace.ID
}

// tryFetchNodeNSRange attempts to return the min and max namespace ids.
// It will return an ErrInvalidNodeLen | ErrInvalidNodeNamespaceOrder
// if the supplied node does not conform to the namespaced hash format.
func (n *NmtHasher) tryFetchNodeNSRange(node []byte) (nsIDRange, error) {
	return n.tryFetchNodeNSRangeVerify(node, true)
}

func (n *NmtHasher) tryFetchNodeNSRangeVerify(node []byte, verify bool) (nsIDRange, error) {
	if verify {
		expectedNodeLen := n.Size()
		nodeLen := len(node)
		if nodeLen != expectedNodeLen {
			return nsIDRange{}, fmt.Errorf("%w: got: %v, want %v", ErrInvalidNodeLen, nodeLen, expectedNodeLen)
		}
	}
	// Extract namespace range - this is the essential work we always need to do
	minNID := namespace.ID(MinNamespace(node, n.NamespaceSize()))
	maxNID := namespace.ID(MaxNamespace(node, n.NamespaceSize()))
	if verify && maxNID.Less(minNID) {
		return nsIDRange{}, fmt.Errorf("%w: max namespace ID %d is less than min namespace ID %d ", ErrInvalidNodeNamespaceOrder, maxNID, minNID)
	}
	return nsIDRange{Min: minNID, Max: maxNID}, nil
}

// ValidateNodeFormat checks whether the supplied node conforms to the
// namespaced hash format and returns an error if not.
func (n *NmtHasher) ValidateNodeFormat(node []byte) error {
	_, err := n.tryFetchNodeNSRange(node)
	return err
}

// tryFetchLeftAndRightNSRange attempts to return the min/max namespace ids of both
// the left and right nodes. It verifies whether left
// and right comply by the namespace hash format, and are correctly ordered
// according to their namespace IDs.
func (n *NmtHasher) tryFetchLeftAndRightNSRanges(left, right []byte) (
	nsIDRange,
	nsIDRange,
	error,
) {
	return n.tryFetchLeftAndRightNSRangesVerify(left, right, true)
}

func (n *NmtHasher) tryFetchLeftAndRightNSRangesVerify(left, right []byte, verify bool) (
	nsIDRange,
	nsIDRange,
	error,
) {
	var lNsRange nsIDRange
	var rNsRange nsIDRange
	var err error

	lNsRange, err = n.tryFetchNodeNSRangeVerify(left, verify)
	if err != nil {
		return lNsRange, rNsRange, err
	}
	rNsRange, err = n.tryFetchNodeNSRangeVerify(right, verify)
	if err != nil {
		return lNsRange, rNsRange, err
	}

	// check the namespace range of the left and right children
	// Skip this expensive validation when we trust the input
	if verify && rNsRange.Min.Less(lNsRange.Max) {
		err = fmt.Errorf("%w: the min namespace ID of the right child %d is less than the max namespace ID of the left child %d", ErrUnorderedSiblings, rNsRange.Min, lNsRange.Max)
	}

	return lNsRange, rNsRange, err
}

// ValidateNodes is a helper function  to verify the
// validity of the inputs of HashNode. It verifies whether left
// and right comply by the namespace hash format, and are correctly ordered
// according to their namespace IDs.
func (n *NmtHasher) ValidateNodes(left, right []byte) error {
	_, _, err := n.tryFetchLeftAndRightNSRanges(left, right)
	return err
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
// slightly changes. Let MAXNID be the maximum possible namespace ID value i.e., 2^NamespaceIDSize-1.
// If the namespace range of the right child is start=end=MAXNID, indicating that it represents the root of a subtree whose leaves all have the namespace ID of `MAXNID`, then exclude the right child from the namespace range calculation. Instead,
// assign the namespace range of the left child as the parent's namespace range.
func (n *NmtHasher) HashNode(left, right []byte) ([]byte, error) {
	// validate the inputs & fetch the namespace ranges
	lRange, rRange, err := n.tryFetchLeftAndRightNSRangesVerify(left, right, true)
	if err != nil {
		return nil, err
	}

	h := n.baseHasher
	h.Reset()

	// compute the namespace range of the parent node
	minNs, maxNs := computeNsRange(lRange.Min, lRange.Max, rRange.Min, rRange.Max, n.ignoreMaxNs, n.precomputedMaxNs)
	// Allocate new buffer (original behavior)
	res := make([]byte, 0, len(minNs)+len(maxNs)+h.Size())
	res = append(res, minNs...)
	res = append(res, maxNs...)

	h.Write(nodePrefixBytes)
	h.Write(left)
	h.Write(right)
	return h.Sum(res), nil
}

func (n *NmtHasher) HashNodeReuse(left, right []byte) ([]byte, error) {
	lRange, rRange, err := n.tryFetchLeftAndRightNSRangesVerify(left, right, false)
	if err != nil {
		return nil, err
	}

	h := n.baseHasher
	h.Reset()

	minNs, maxNs := computeNsRange(lRange.Min, lRange.Max, rRange.Min, rRange.Max, n.ignoreMaxNs, n.precomputedMaxNs)

	h.Write(nodePrefixBytes)
	h.Write(left)
	h.Write(right)

	var buffer []byte
	if cap(left) >= cap(right) {
		buffer = left
	} else {
		buffer = right
	}

	requiredSize := len(minNs) + len(maxNs) + h.Size()
	if cap(buffer) < requiredSize {
		newCap := 2 * requiredSize
		buffer = make([]byte, 0, newCap)
	} else {
		buffer = buffer[:0]
	}
	buffer = append(buffer, minNs...)
	buffer = append(buffer, maxNs...)
	return h.Sum(buffer), nil
}

// computeNsRange computes the namespace range of the parent node based on the namespace ranges of its left and right children.
func computeNsRange(leftMinNs, leftMaxNs, rightMinNs, rightMaxNs []byte, ignoreMaxNs bool, precomputedMaxNs namespace.ID) (minNs []byte, maxNs []byte) {
	minNs = leftMinNs
	maxNs = rightMaxNs
	if ignoreMaxNs && fastEqual8(precomputedMaxNs, rightMinNs) {
		maxNs = leftMaxNs
	}
	return minNs, maxNs
}

// fastEqual8 optimizes equality comparison for 8-byte namespaces
func fastEqual8(a, b []byte) bool {
	if len(a) == 8 && len(b) == 8 {
		return binary.BigEndian.Uint64(a) == binary.BigEndian.Uint64(b)
	}
	return bytes.Equal(a, b)
}
