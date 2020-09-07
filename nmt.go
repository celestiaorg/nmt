// Package nmt contains an NMT implementation.
package nmt

import (
	"bytes"
	"errors"
	"fmt"
	"hash"

	"github.com/liamsi/merkletree"

	"github.com/lazyledger/nmt/internal"
	"github.com/lazyledger/nmt/namespace"
)

const (
	LeafPrefix = 0
	NodePrefix = 1
)

var (
	ErrMismatchedNamespaceSize = errors.New("mismatching namespace sizes")
	ErrInvalidPushOrder        = errors.New("pushed data has to be lexicographically ordered by namespace IDs")
)

type Options struct {
	InitialCapacity    int
	NamespaceIDSize    namespace.IDSize
	IgnoreMaxNamespace bool
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
// Defaults to false.
func IgnoreMaxNamespace(ignore bool) Option {
	return func(opts *Options) {
		opts.IgnoreMaxNamespace = ignore
	}
}

type NamespacedMerkleTree struct {
	treeHasher internal.NmtHasher
	tree       *merkletree.Tree

	// just cache stuff until we pass in a store and keep all nodes in there
	leaves     []namespace.Data
	leafHashes [][]byte
	// this can be used to efficiently lookup the range for an
	// existing namespace without iterating through the leaves
	namespaceRanges map[string]merkletree.LeafRange
	minNID          namespace.ID
	maxNID          namespace.ID
}

// New initializes a namespaced Merkle tree using the given base hash function
// and for the given namespace size (number of bytes).
// If the namespace size is 0 this corresponds to a regular non-namespaced
// Merkle tree.
func New(h hash.Hash, setters ...Option) *NamespacedMerkleTree {
	// default options:
	opts := &Options{
		InitialCapacity: 128,
		NamespaceIDSize: 32,
	}

	for _, setter := range setters {
		setter(opts)
	}
	treeHasher := internal.NewNmtHasher(opts.NamespaceIDSize, h)
	return &NamespacedMerkleTree{
		treeHasher:      treeHasher,
		tree:            merkletree.NewFromTreehasher(treeHasher),
		leaves:          make([]namespace.Data, 0, opts.InitialCapacity),
		leafHashes:      make([][]byte, 0, opts.InitialCapacity),
		namespaceRanges: make(map[string]merkletree.LeafRange),
		minNID:          bytes.Repeat([]byte{0xFF}, int(opts.NamespaceIDSize)),
		maxNID:          bytes.Repeat([]byte{0x00}, int(opts.NamespaceIDSize)),
	}
}

// Prove leaf at index.
// Note this is not really NMT specific but the tree supports inclusions proofs
// like any vanilla Merkle tree.
func (n NamespacedMerkleTree) Prove(index int) (Proof, error) {
	subTreeHasher := internal.NewCachedSubtreeHasher(n.leafHashes, n.treeHasher)
	// TODO: store nodes and re-use the hashes instead recomputing parts of the tree here
	proof, err := merkletree.BuildRangeProof(index, index+1, subTreeHasher)
	if err != nil {
		return NewEmptyRangeProof(), err
	}

	return NewInclusionProof(index, index+1, proof), nil
}

// ProveNamespace returns a range proof for the given NamespaceID.
//
// In case the underlying tree contains leaves with the given namespace
// their start and end index will be returned together with a range proof and
// the found leaves. In that case the returned leafHash will be nil.
//
// If the tree does not have any entries with the given Namespace ID,
// but the namespace is within the range of the tree's min and max namespace,
// this will be proven by returning the (namespaced or rather flagged)
// hash of the leaf that is in the range instead of the namespace.
//
// In the case (nID < minNID) or (maxNID < nID) we do not
// generate any proof and we return an empty range (0,0) to
// indicate that this namespace is not contained in the tree.
func (n NamespacedMerkleTree) ProveNamespace(nID namespace.ID) (Proof, error) {
	// In the cases (nID < minNID) or (maxNID < nID),
	// return empty range and no proof:
	if nID.Less(n.minNID) || n.maxNID.Less(nID) {
		return NewEmptyRangeProof(), nil
	}

	found, proofStart, proofEnd := n.foundInRange(nID)
	if !found {
		// To generate a proof for an absence we calculate the
		// position of the leaf that is in the place of where
		// the namespace would be in:
		proofStart = n.calculateAbsenceIndex(nID)
		proofEnd = proofStart + 1
	}
	// At this point we either found the namespace in the tree or calculated
	// the range it would be in (to generate a proof of absence and to return
	// the corresponding leaf hashes).
	subTreeHasher := internal.NewCachedSubtreeHasher(n.leafHashes, n.treeHasher)
	var err error
	proof, err := merkletree.BuildRangeProof(proofStart, proofEnd, subTreeHasher)
	if err != nil {
		// This should never happen.
		// TODO would be good to back this by more tests and fuzzing.
		return Proof{}, fmt.Errorf(
			"unexpected err: %w on nID: %v, range: [%v, %v)",
			err,
			nID,
			proofStart,
			proofEnd,
		)
	}

	if found {
		return NewInclusionProof(proofStart, proofEnd, proof), nil
	}
	return NewAbsenceProof(proofStart, proofEnd, proof, n.leafHashes[proofStart]), nil
}

// Get returns leaves for the given namespace.ID.
func (n NamespacedMerkleTree) Get(nID namespace.ID) []namespace.Data {
	_, start, end := n.foundInRange(nID)
	return n.leaves[start:end]
}

// GetWithProof is a convenience method returns leaves for the given namespace.ID
// together with the proof for that namespace. It returns the same result
// as calling the combination of Get(nid) and ProveNamespace(nid).
func (n NamespacedMerkleTree) GetWithProof(nID namespace.ID) ([]namespace.Data, Proof, error) {
	data := n.Get(nID)
	proof, err := n.ProveNamespace(nID)
	return data, proof, err
}

func (n NamespacedMerkleTree) calculateAbsenceIndex(nID namespace.ID) int {
	var prevLeaf namespace.Data
	for index, curLeaf := range n.leaves {
		if index == 0 {
			prevLeaf = curLeaf
			continue
		}
		prevNs := prevLeaf.NamespaceID()
		currentNs := curLeaf.NamespaceID()
		// Note that here we would also care for the case
		// current < nId < prevNs
		// but we only allow pushing leaves with ascending namespaces;
		// i.e. prevNs <= currentNs is always true.
		// Also we only check for strictly smaller: prev < nid < current
		// because if we either side was equal, we would have found the
		// namespace before.
		if prevNs.Less(nID) && nID.Less(currentNs) {
			return index
		}
		prevLeaf = curLeaf
	}
	// the case (nID < minNID) or (maxNID < nID) should be handled
	// before calling this private helper!
	panic("calculateAbsenceIndex() called although (nID < minNID) or (maxNID < nID) for provided nID")
}

func (n *NamespacedMerkleTree) foundInRange(nID namespace.ID) (bool, int, int) {
	// This is a faster version of this code snippet:
	// https://github.com/lazyledger/lazyledger-prototype/blob/2aeca6f55ad389b9d68034a0a7038f80a8d2982e/simpleblock.go#L106-L117
	foundRng, found := n.namespaceRanges[string(nID)]
	// XXX casting from uint64 to int is kinda crappy but nebolousLabs'
	// range proof api requires int params only to convert them to uint64 ...
	return found, int(foundRng.Start), int(foundRng.End)
}

// NamespaceSize returns the underlying namespace size. Note that
// all namespaced data is expected to have the same namespace size.
func (n NamespacedMerkleTree) NamespaceSize() namespace.IDSize {
	return n.treeHasher.NamespaceSize()
}

// Push adds data with the corresponding namespace ID to the tree.
// Returns an error if the namespace ID size of the input
// does not match the tree's NamespaceSize() or the leaves are not pushed in
// order (i.e. lexicographically sorted by namespace ID).
func (n *NamespacedMerkleTree) Push(data namespace.Data) error {
	got, want := data.NamespaceID().Size(), n.NamespaceSize()
	if got != want {
		return fmt.Errorf("%w: got: %v, want: %v", ErrMismatchedNamespaceSize, got, want)
	}
	// ensure pushed data doesn't have a smaller namespace than the previous one:
	curSize := len(n.leaves)
	if curSize > 0 {
		if data.NamespaceID().Less(n.leaves[curSize-1].NamespaceID()) {
			return fmt.Errorf(
				"%w: last namespace: %x, pushed: %x",
				ErrInvalidPushOrder,
				n.leaves[curSize-1].NamespaceID(),
				data.NamespaceID(),
			)
		}
	}
	leafData := append(data.NamespaceID(), data.Data()...)
	n.tree.Push(leafData)
	// update relevant "caches":
	n.leaves = append(n.leaves, data)
	n.leafHashes = append(n.leafHashes, n.treeHasher.HashLeaf(leafData))
	n.updateNamespaceRanges()
	n.updateMinMaxID(data)
	return nil
}

// Return the namespaced Merkle Tree's root together with the
// min. and max. namespace ID.
func (n *NamespacedMerkleTree) Root() namespace.IntervalDigest {
	if len(n.leaves) == 0 {
		return n.treeHasher.EmptyRoot()
	}
	return namespace.IntervalDigestFromBytes(n.NamespaceSize(), n.tree.Root())
}

func (n *NamespacedMerkleTree) updateNamespaceRanges() {
	if len(n.leaves) > 0 {
		lastIndex := len(n.leaves) - 1
		lastPushed := n.leaves[lastIndex]
		lastNsStr := string(lastPushed.NamespaceID())
		lastRange, found := n.namespaceRanges[lastNsStr]
		if !found {
			n.namespaceRanges[lastNsStr] = merkletree.LeafRange{
				Start: uint64(lastIndex),
				End:   uint64(lastIndex + 1),
			}
		} else {
			n.namespaceRanges[lastNsStr] = merkletree.LeafRange{
				Start: lastRange.Start,
				End:   lastRange.End + 1,
			}
		}
	}
}

func (n *NamespacedMerkleTree) updateMinMaxID(data namespace.Data) {
	if data.NamespaceID().Less(n.minNID) {
		n.minNID = data.NamespaceID()
	}
	if n.maxNID.Less(data.NamespaceID()) {
		n.maxNID = data.NamespaceID()
	}
}
