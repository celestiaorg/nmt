package simple

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"

	"github.com/lazyledger/nmt/namespace"
	"github.com/lazyledger/nmt/storage"
)

var (
	ErrMismatchedNamespaceSize = errors.New("mismatching namespace sizes")
	ErrInvalidPushOrder        = errors.New("pushed data has to be lexicographically ordered by namespace IDs")
)

var cachedMaxNs = namespace.ID(bytes.Repeat([]byte{0xFF}, 8))

type NMTree struct {
	nidSize int
	leaves  [][]byte
	store   storage.NodeStorer
}

func NewNMTree(nidSize namespace.IDSize) *NMTree {
	return &NMTree{
		nidSize: int(nidSize),
		leaves:  make([][]byte, 0),
		store:   storage.NewInMemoryNodeStore(nidSize),
	}
}

func (n *NMTree) Push(id namespace.ID, data []byte) error {
	err := n.validateNamespace(id)
	if err != nil {
		return err
	}
	leafData := append(id, data...)
	n.leaves = append(n.leaves, leafData)
	return nil
}

func (n *NMTree) Root() []byte {
	return computeRoot(n.leaves, n.nidSize, n.store)
}

func (n *NMTree) validateNamespace(id namespace.ID) error {
	if id == nil {
		return errors.New("namespace.ID can not be empty")
	}
	if id.Size() != namespace.IDSize(n.nidSize) {
		return fmt.Errorf("%w: got: %v, want: %v", ErrMismatchedNamespaceSize, id.Size(), n.nidSize)
	}
	curSize := len(n.leaves)
	if curSize > 0 {
		if id.Less(n.leaves[curSize-1][:n.nidSize]) {
			return fmt.Errorf(
				"%w: last namespace: %x, pushed: %x",
				ErrInvalidPushOrder,
				n.leaves[curSize-1][:n.nidSize],
				id,
			)
		}
	}
	return nil
}

func computeRoot(items [][]byte, nidSize int, store storage.NodeStorer) []byte {
	switch len(items) {
	case 0:
		emptyHash, val := emptyHash(nidSize)
		store.Put(emptyHash, val)
		return emptyHash
	case 1:
		hash, val := leafHash(items[0], nidSize)
		store.Put(hash, val)
		return hash
	default:
		k := getSplitPoint(int64(len(items)))
		left := computeRoot(items[:k], nidSize, store)
		right := computeRoot(items[k:], nidSize, store)
		parentHash, val := innerHash(left, right, nidSize)
		store.Put(parentHash, val)

		return parentHash
	}
}

func getSplitPoint(length int64) int64 {
	if length < 1 {
		panic("Trying to split a tree with size < 1")
	}
	uLength := uint(length)
	bitlen := bits.Len(uLength)
	k := int64(1 << uint(bitlen-1))
	if k == length {
		k >>= 1
	}
	return k
}

var (
	leafPrefix  = []byte{0}
	innerPrefix = []byte{1}
)

func emptyHash(nidSize int) ([]byte, []byte) {
	emptyNs := bytes.Repeat([]byte{0}, nidSize)
	h := sha256.New().Sum(nil)
	digest := append(append(emptyNs, emptyNs...), h...)

	return digest, nil
}

func leafHash(leaf []byte, nidSize int) ([]byte, []byte) {
	h := sha256.New()
	nID := leaf[:nidSize]
	data := leaf[nidSize:]
	res := append(append(make([]byte, 0), nID...), nID...)
	data = append(leafPrefix, data...)
	h.Write(data)
	hash := h.Sum(res)

	return hash, data
}

func innerHash(l []byte, r []byte, nidSize int) ([]byte, []byte) {

	h := sha256.New()

	flagLen := 2 * nidSize
	leftMinNs, leftMaxNs := l[:nidSize], l[nidSize:flagLen]
	rightMinNs, rightMaxNs := r[:nidSize], r[nidSize:flagLen]

	minNs := min(leftMinNs, rightMinNs)
	var maxNs []byte
	if cachedMaxNs.Equal(leftMinNs) {
		maxNs = cachedMaxNs
	} else if cachedMaxNs.Equal(rightMinNs) {
		maxNs = leftMaxNs
	} else {
		maxNs = max(leftMaxNs, rightMaxNs)
	}

	res := append(append(make([]byte, 0), minNs...), maxNs...)

	// Note this seems a little faster than calling several Write()s on the
	// underlying Hash function (see: https://github.com/google/trillian/pull/1503):
	b := append(append(append(
		make([]byte, 0, 1+len(l)+len(r)),
		innerPrefix...),
		l...),
		r...)
	//nolint:errcheck
	h.Write(b)
	hash := h.Sum(res)

	return hash, b
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
