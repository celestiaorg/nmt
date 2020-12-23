package simple

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"math/bits"

	"github.com/lazyledger/nmt/namespace"
	"github.com/lazyledger/nmt/storage"
)

var (
	ErrMismatchedNamespaceSize = errors.New("mismatching namespace sizes")
	ErrInvalidPushOrder        = errors.New("pushed data has to be lexicographically ordered by namespace IDs")
)

type Options struct {
	InitialCapacity    int
	NamespaceIDSize    namespace.IDSize
	IgnoreMaxNamespace bool
	NodeStore          storage.NodeStorer
}

type Option func(*Options)

// InitialCapacity sets the capacity of the internally used slice(s) to
// the passed in initial value (defaults is 128).
func InitialCapacity(cap int) Option {
	if cap < 0 {
		panic("Got invalid capacity. Expected int greater or equal to 0.")
	}
	return func(opts *Options) {
		opts.InitialCapacity = cap
	}
}

// NamespaceIDSize sets the size of namespace IDs (in bytes) used by this tree.
// Defaults to 32 bytes.
func NamespaceIDSize(size int) Option {
	if size < 0 || size > namespace.IDMaxSize {
		panic("Got invalid namespace.IDSize. Expected 0 <= size <= namespace.IDMaxSize.")
	}
	return func(opts *Options) {
		opts.NamespaceIDSize = namespace.IDSize(size)
	}
}

// IgnoreMaxNamespace sets whether the largest possible namespace.ID MAX_NID should be 'ignored'.
// If set to true, this allows for shorter proofs in particular use-cases.
// E.g., see: https://github.com/lazyledger/lazyledger-specs/blob/master/specs/data_structures.md#namespace-merkle-tree
// Defaults to true.
func IgnoreMaxNamespace(ignore bool) Option {
	return func(opts *Options) {
		opts.IgnoreMaxNamespace = ignore
	}
}

func NodeStore(store storage.NodeStorer) Option {
	return func(opts *Options) {
		opts.NodeStore = store
	}
}

type NamespacedMerkleTree struct {
	treeHasher      NmtHasher
	namespaceRanges map[string]leafRange
	// TODO: consolidate leaves with store:
	leaves [][]byte
	store  storage.NodeStorer

	minNID namespace.ID
	maxNID namespace.ID
}

func New(h hash.Hash, setters ...Option) *NamespacedMerkleTree {
	// default options:
	opts := &Options{
		InitialCapacity:    128,
		NamespaceIDSize:    8,
		IgnoreMaxNamespace: true,
	}
	for _, setter := range setters {
		setter(opts)
	}
	if opts.NodeStore == nil {
		opts.NodeStore = storage.NewInMemoryNodeStore(opts.NamespaceIDSize)
	}
	return &NamespacedMerkleTree{
		treeHasher:      NewNmtHasher(h, opts.NamespaceIDSize, opts.IgnoreMaxNamespace),
		namespaceRanges: make(map[string]leafRange),
		leaves:          make([][]byte, 0),
		store:           storage.NewInMemoryNodeStore(opts.NamespaceIDSize),
		minNID:          bytes.Repeat([]byte{0xFF}, int(opts.NamespaceIDSize)),
		maxNID:          bytes.Repeat([]byte{0x00}, int(opts.NamespaceIDSize)),
	}
}

func (n *NamespacedMerkleTree) Push(id namespace.ID, data []byte) error {
	err := n.validateNamespace(id)
	if err != nil {
		return err
	}
	leafData := append(id, data...)
	n.leaves = append(n.leaves, leafData)
	return nil
}

func (n *NamespacedMerkleTree) Root() []byte {
	return n.computeRoot(n.leaves)
}

func (n *NamespacedMerkleTree) validateNamespace(id namespace.ID) error {
	if id == nil {
		return errors.New("namespace.ID can not be empty")
	}
	nidSize := n.treeHasher.NamespaceSize()
	if id.Size() != nidSize {
		return fmt.Errorf("%w: got: %v, want: %v", ErrMismatchedNamespaceSize, id.Size(), nidSize)
	}
	curSize := len(n.leaves)
	if curSize > 0 {
		if id.Less(n.leaves[curSize-1][:nidSize]) {
			return fmt.Errorf(
				"%w: last namespace: %x, pushed: %x",
				ErrInvalidPushOrder,
				n.leaves[curSize-1][:nidSize],
				id,
			)
		}
	}
	return nil
}

func (n *NamespacedMerkleTree) updateNamespaceRanges() {
	if len(n.leaves) > 0 {
		lastIndex := len(n.leaves) - 1
		lastPushed := n.leaves[lastIndex]
		lastNsStr := string(lastPushed[:n.treeHasher.NamespaceSize()])
		lastRange, found := n.namespaceRanges[lastNsStr]
		if !found {
			n.namespaceRanges[lastNsStr] = leafRange{
				start: uint64(lastIndex),
				end:   uint64(lastIndex + 1),
			}
		} else {
			n.namespaceRanges[lastNsStr] = leafRange{
				start: lastRange.start,
				end:   lastRange.end + 1,
			}
		}
	}
}

type leafRange struct {
	start, end uint64
}

func (n *NamespacedMerkleTree) computeRoot(items [][]byte) []byte {
	switch len(items) {
	case 0:
		emptyHash, val := n.treeHasher.EmptyRoot()
		n.store.Put(emptyHash, val)
		return emptyHash
	case 1:
		hash, val := n.treeHasher.HashLeaf(items[0])
		n.store.Put(hash, val)
		return hash
	default:
		k := getSplitPoint(int64(len(items)))
		left := n.computeRoot(items[:k])
		right := n.computeRoot(items[k:])
		parentHash, val := n.treeHasher.HashNode(left, right)
		n.store.Put(parentHash, val)

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
