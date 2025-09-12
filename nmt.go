// Package nmt contains an NMT implementation.
// The specifications can be found in https://github.com/celestiaorg/nmt/blob/main/docs/spec/nmt.md.
package nmt

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"math/bits"
	"unsafe"

	"github.com/celestiaorg/nmt/namespace"
)

// bytePool is a simple non-thread-safe pool of byte slices
type bytePool struct {
	pool [][]byte
}

// newBytePool creates a new byte pool
func newBytePool() *bytePool {
	return &bytePool{
		pool: make([][]byte, 0),
	}
}

// put adds a byte slice to the pool
func (p *bytePool) put(b []byte) {
	if b == nil {
		return
	}
	p.pool = append(p.pool, b)
}

// get retrieves a byte slice from the pool
// Returns nil if the pool is empty
func (p *bytePool) get() []byte {
	if len(p.pool) == 0 {
		return nil
	}

	lastIdx := len(p.pool) - 1
	b := p.pool[lastIdx]
	p.pool = p.pool[:lastIdx]
	return b
}

const (
	DefaultNamespaceIDLen = 8
	DefaultCapacity       = 128
)

var (
	ErrInvalidRange     = errors.New("invalid proof range")
	ErrInvalidPushOrder = errors.New("pushed data has to be lexicographically ordered by namespace IDs")
)

type NodeVisitorFn = func(hash []byte, children ...[]byte)

type Options struct {
	// InitialCapacity indicates the initial number of leaves in the tree
	InitialCapacity int
	// NamespaceIDSize is the size of a namespace ID in bytes
	NamespaceIDSize namespace.IDSize
	// The "IgnoreMaxNamespace" flag influences the calculation of the namespace
	// ID range for intermediate nodes in the tree. This flag signals that, when
	// determining the upper limit of the namespace ID range for a tree node,
	// the maximum possible namespace ID (equivalent to "NamespaceIDSize" bytes
	// of 0xFF, or 2^NamespaceIDSize-1) should be omitted if feasible. For a
	// more in-depth understanding of this field, refer to the "HashNode" method
	// in the "Hasher.
	IgnoreMaxNamespace bool
	NodeVisitor        NodeVisitorFn
	Hasher             Hasher
}

type Option func(*Options)

// InitialCapacity sets the capacity of the internally used slice(s) to the
// passed in initial value (defaults is 128).
func InitialCapacity(capacity int) Option {
	if capacity < 0 {
		panic("Got invalid capacity. Expected int greater or equal to 0.")
	}
	return func(opts *Options) {
		opts.InitialCapacity = capacity
	}
}

// NamespaceIDSize sets the size of namespace IDs (in bytes) used by this tree.
// Defaults to 8 bytes.
func NamespaceIDSize(size int) Option {
	if size < 0 || size > namespace.IDMaxSize {
		panic("Got invalid namespace.IDSize. Expected 0 <= size <= namespace.IDMaxSize.")
	}
	return func(opts *Options) {
		opts.NamespaceIDSize = namespace.IDSize(size)
	}
}

// IgnoreMaxNamespace sets whether the largest possible namespace.ID MAX_NID
// should be 'ignored'. If set to true, this allows for shorter proofs in
// particular use-cases. E.g., see:
// https://github.com/celestiaorg/celestiaorg-specs/blob/main/specs/data_structures.md#namespace-merkle-tree
// Defaults to true.
func IgnoreMaxNamespace(ignore bool) Option {
	return func(opts *Options) {
		opts.IgnoreMaxNamespace = ignore
	}
}

func NodeVisitor(nodeVisitorFn NodeVisitorFn) Option {
	return func(opts *Options) {
		opts.NodeVisitor = nodeVisitorFn
	}
}

// CustomHasher replaces the default hasher.
func CustomHasher(h Hasher) Option {
	return func(o *Options) {
		o.Hasher = h
	}
}

type NamespacedMerkleTree struct {
	treeHasher  Hasher
	reuseHasher memoryReuseHasher
	visit       NodeVisitorFn

	// just cache stuff until we pass in a store and keep all nodes in there
	// currently, only leaves and leafHashes are stored:

	// leaves holds the list of namespace-prefixed data elements that have been
	// added to the tree, in the order of their insertion. Each
	// namespace-prefixed data item is represented as a byte slice.
	leaves [][]byte
	//  leafHashes stores the namespace hash of the leaves, calculated either
	//  through the Root() or the computeLeafHashesIfNecessary methods.
	leafHashes [][]byte
	pool       *bytePool

	// namespaceRanges can be used to efficiently look up the range for an
	// existing namespace without iterating through the leaves. The map key is
	// the string representation of a namespace.ID and the LeafRange indicates
	// the range of the leaves matching that namespace ID in the tree
	namespaceRanges map[string]LeafRange
	// minNID is the minimum namespace ID of the leaves
	minNID namespace.ID
	// maxNID is the maximum namespace ID of the leaves
	maxNID namespace.ID

	// rawRoot caches the value of the tree root whenever the Root() method is
	// invoked. It's important to note that rawRoot may become outdated and may
	// not accurately reflect the current state of the leaves.
	rawRoot []byte
}

// New initializes a namespaced Merkle tree using the given base hash function
// and for the given namespace size (number of bytes). If the namespace size is
// 0 this corresponds to a regular non-namespaced Merkle tree.
func New(h hash.Hash, setters ...Option) *NamespacedMerkleTree {
	// default options:
	opts := &Options{
		InitialCapacity:    DefaultCapacity,
		NamespaceIDSize:    DefaultNamespaceIDLen,
		IgnoreMaxNamespace: true,
		NodeVisitor:        nil,
	}

	for _, setter := range setters {
		setter(opts)
	}

	// first create the default hasher using the updated options
	hasher := NewNmtHasher(h, opts.NamespaceIDSize, opts.IgnoreMaxNamespace)
	opts.Hasher = hasher

	// set the options a second time to replace the hasher if needed
	for _, setter := range setters {
		setter(opts)
	}
	var reuseHasher memoryReuseHasher
	// in case we provide the NMTHasher, we can use buffers for hashing
	if convHasher, ok := opts.Hasher.(memoryReuseHasher); ok {
		reuseHasher = convHasher
	}
	return &NamespacedMerkleTree{
		treeHasher:      opts.Hasher,
		reuseHasher:     reuseHasher,
		visit:           opts.NodeVisitor,
		leaves:          make([][]byte, 0, opts.InitialCapacity),
		leafHashes:      make([][]byte, 0, opts.InitialCapacity),
		pool:            newBytePool(),
		namespaceRanges: make(map[string]LeafRange),
		minNID:          bytes.Repeat([]byte{0xFF}, int(opts.NamespaceIDSize)),
		maxNID:          bytes.Repeat([]byte{0x00}, int(opts.NamespaceIDSize)),
	}
}

// Prove returns a NMT inclusion proof for the leaf at the supplied index. Note
// this is not really NMT specific but the tree supports inclusions proofs like
// any vanilla Merkle tree. Prove is a thin wrapper around the ProveRange.
// If the supplied index is invalid i.e., if index < 0 or index > n.Size(), then Prove returns an ErrInvalidRange error. Any other errors rather than this are irrecoverable and indicate an illegal state of the tree (n).
func (n *NamespacedMerkleTree) Prove(index int) (Proof, error) {
	return n.ProveRange(index, index+1)
}

// ProveRange returns a Merkle inclusion proof for a specified range of leaves,
// from start to end exclusive. The returned Proof structure contains the nodes
// field, which holds the necessary tree nodes for the Merkle range proof in an
// in-order traversal order. These nodes include the namespaced hash of the left
// siblings for the proof of the leaf at index start, and the namespaced hash of
// the right siblings for the proof of the leaf at index end.
//
// If the specified range [start, end) exceeds the current range of leaves in
// the tree, ProveRange returns an error together with an empty Proof with empty
// nodes and start and end fields set to 0.
//
// The isMaxNamespaceIDIgnored field of the Proof reflects the ignoreMaxNs field
// of n.treeHasher. When set to true, this indicates that the proof was
// generated using a modified version of the namespace hash with a custom
// namespace ID range calculation. For more information on this, please refer to
// the HashNode method in the Hasher.
// If the supplied (start, end) range is invalid i.e., if start < 0 or end > n.Size() or start >= end,
// then ProveRange returns an ErrInvalidRange error. Any errors rather than ErrInvalidRange are irrecoverable and indicate an illegal state of the tree (n).
func (n *NamespacedMerkleTree) ProveRange(start, end int) (Proof, error) {
	isMaxNsIgnored := n.treeHasher.IsMaxNamespaceIDIgnored()
	// TODO: store nodes and re-use the hashes instead recomputing parts of the
	// tree here
	if err := n.validateRange(start, end); err != nil {
		return NewEmptyRangeProof(isMaxNsIgnored), err
	}
	proof, err := n.buildRangeProof(start, end)
	if err != nil {
		return Proof{}, err
	}
	return NewInclusionProof(start, end, proof, isMaxNsIgnored), nil
}

// ProveNamespace returns a range proof for the given NamespaceID.
//
// case 1) If the namespace nID is out of the range of the tree's min and max
// namespace i.e., (nID < n.minNID) or (n.maxNID < nID) ProveNamespace returns an empty
// Proof with empty nodes and the range (0,0) i.e., Proof.start = 0 and
// Proof.end = 0 to indicate that this namespace is not contained in the tree.
//
// case 2) If the namespace nID is within the range of the tree's min and max
// namespace i.e., n.minNID<= n.ID <=n.maxNID and the tree does not have any
// entries with the given Namespace ID nID, this will be proven by returning the
// inclusion/range Proof of the (namespaced or rather flagged) hash of the leaf
// of the tree 1) with the smallest namespace ID that is larger than nID and 2)
// the namespace ID of the leaf to the left of it is smaller than the nid. The nodes
// field of the returned Proof structure is populated with the Merkle inclusion
// proof. the leafHash field of the returned Proof will contain the namespaced
// hash of such leaf. The start and end fields of the Proof are set to the
// indices of the identified leaf. The start field is set to the index of the
// leaf, and the end field is set to the index of the leaf + 1.
//
// case 3) In case the underlying tree contains leaves with the given namespace
// their start and end (end is non-inclusive) index will be returned together
// with a range proof for [start, end). In that case the leafHash field of the
// returned Proof will be nil.
//
// The isMaxNamespaceIDIgnored field of the Proof reflects the ignoreMaxNs field
// of n.treeHasher. When set to true, this indicates that the proof was
// generated using a modified version of the namespace hash with a custom
// namespace ID range calculation. For more information on this, please refer to
// the HashNode method in the Hasher.
// Any error returned by this method is irrecoverable and indicates an illegal state of the tree (n).
func (n *NamespacedMerkleTree) ProveNamespace(nID namespace.ID) (Proof, error) {
	isMaxNsIgnored := n.treeHasher.IsMaxNamespaceIDIgnored()

	// check if the tree is empty
	if n.Size() == 0 {
		return NewEmptyRangeProof(isMaxNsIgnored), nil
	}

	// compute the root of the tree
	root, err := n.Root()
	if err != nil {
		return Proof{}, fmt.Errorf("failed to get root: %w", err)
	}
	// extract the min and max namespace of the tree from the root
	treeMinNs := namespace.ID(MinNamespace(root, n.NamespaceSize()))
	treeMaxNs := namespace.ID(MaxNamespace(root, n.NamespaceSize()))

	// case 1) In the cases (n.nID < treeMinNs) or (treeMaxNs < nID), return empty
	// range proof
	if nID.Less(treeMinNs) || treeMaxNs.Less(nID) {
		return NewEmptyRangeProof(isMaxNsIgnored), nil
	}

	// find the range of indices of leaves with the given nID
	found, proofStart, proofEnd := n.foundInRange(nID)

	// case 2)
	if !found {
		// To generate a proof for an absence we calculate the position of the
		// leaf that is in the place of where the namespace would be in:
		proofStart = n.calculateAbsenceIndex(nID)
		proofEnd = proofStart + 1
	}

	// case 3) At this point we either found leaves with the namespace nID in
	// the tree or calculated the range it would be in (to generate a proof of
	// absence and to return the corresponding leaf hashes).

	proof, err := n.buildRangeProof(proofStart, proofEnd)
	if err != nil {
		return Proof{}, err
	}

	if found {
		return NewInclusionProof(proofStart, proofEnd, proof, isMaxNsIgnored), nil
	}

	return NewAbsenceProof(proofStart, proofEnd, proof, n.leafHashes[proofStart], isMaxNsIgnored), nil
}

// validateRange validates the range [start, end) against the size of the tree.
// start is inclusive and end is non-inclusive.
func (n *NamespacedMerkleTree) validateRange(start, end int) error {
	if start < 0 || start >= end || end > n.Size() {
		return ErrInvalidRange
	}
	return nil
}

// buildRangeProof returns the nodes (as byte slices) in the range proof of the
// supplied range i.e., [proofStart, proofEnd) where proofEnd is non-inclusive.
// The nodes are ordered according to in order traversal of the namespaced tree.
// Any errors returned by this method are irrecoverable and indicate an illegal state of the tree (n).
func (n *NamespacedMerkleTree) buildRangeProof(proofStart, proofEnd int) ([][]byte, error) {
	proof := [][]byte{} // it is the list of nodes hashes (as byte slices) with no index
	var recurse func(start, end int, includeNode bool) ([]byte, error)

	// validate the range
	if err := n.validateRange(proofStart, proofEnd); err != nil {
		return nil, err
	}

	// start, end are indices of leaves in the tree hence they should be within
	// the size of the tree i.e., less than or equal to n.Size()
	// includeNode indicates whether the hash of the current subtree (covering
	// the supplied range i.e., [start, end)) or one of its constituent subtrees
	// should be part of the proof
	recurse = func(start, end int, includeNode bool) ([]byte, error) {
		if start >= n.Size() {
			return nil, nil
		}

		// reached a leaf
		if end-start == 1 {
			leafHash := n.leafHashes[start]
			// if the index of the leaf node is out of the queried range i.e. ,
			// [proofStart, proofEnd) and if the leaf is required as part of the
			// proof i.e., includeNode == true
			if (start < proofStart || start >= proofEnd) && includeNode {
				// add the leafHash to the proof
				proof = append(proof, leafHash)
			}
			// if the index of the leaf is within the queried range i.e.,
			// [proofStart, proofEnd] OR if the leaf is not required as part of
			// the proof i.e., includeNode == false
			return leafHash, nil
		}

		// newIncludeNode indicates whether one of the subtrees of the current
		// subtree [start, end) may have an overlap with the queried proof range
		// i.e., [proofStart, proofEnd)
		newIncludeNode := includeNode
		// check whether the subtree representing the [start, end) range of
		// leaves has overlap with the queried proof range i.e., [proofStart,
		// proofEnd) if there is no overlap
		if (end <= proofStart || start >= proofEnd) && includeNode {
			// setting newIncludeNode to false indicates that none of the
			// subtrees (left and right) of the current subtree are required for
			// the proof because the range of the leaves they cover have no
			// overlap with the queried proof range i.e., [proofStart, proofEnd)
			newIncludeNode = false
		}

		// recursively get left and right subtree
		k := getSplitPoint(end - start)

		left, err := recurse(start, start+k, newIncludeNode)
		if err != nil {
			return nil, err
		}
		right, err := recurse(start+k, end, newIncludeNode)
		if err != nil {
			return nil, err
		}

		// only right leaf/subtree can be non-existent
		var hash []byte
		if right == nil {
			hash = left
		} else {
			var err error
			hash, err = n.treeHasher.HashNode(left, right)
			if err != nil { // if HashNode returns an error, it is a bug
				return nil, err // this should never happen if the Push method is used to add leaves to the tree
			}
		}

		// if the hash of the subtree representing [start, end) should be part
		// of the proof but not its left and right subtrees
		if includeNode && !newIncludeNode {
			proof = append(proof, hash)
		}

		return hash, nil
	}

	fullTreeSize := getSplitPoint(n.Size()) * 2
	if fullTreeSize < 1 {
		fullTreeSize = 1
	}
	if _, err := recurse(0, fullTreeSize, true); err != nil {
		return nil, err
	}
	return proof, nil
}

// Get returns leaves for the given namespace.ID.
func (n *NamespacedMerkleTree) Get(nID namespace.ID) [][]byte {
	_, start, end := n.foundInRange(nID)
	return n.leaves[start:end]
}

// GetWithProof is a convenience method returns leaves for the given
// namespace.ID together with the proof for that namespace. It returns the same
// result as calling the combination of Get(nid) and ProveNamespace(nid).
func (n *NamespacedMerkleTree) GetWithProof(nID namespace.ID) ([][]byte, Proof, error) {
	data := n.Get(nID)
	proof, err := n.ProveNamespace(nID)
	return data, proof, err
}

// calculateAbsenceIndex returns the index of a leaf of the tree that 1) its
// namespace ID is the smallest namespace ID larger than nID and 2) the
// namespace ID of the leaf to the left of it is smaller than the nID.
func (n *NamespacedMerkleTree) calculateAbsenceIndex(nID namespace.ID) int {
	nidSize := n.treeHasher.NamespaceSize()
	var prevLeaf []byte

	for index, curLeaf := range n.leaves {
		if index == 0 {
			prevLeaf = curLeaf
			continue
		}
		prevNs := namespace.ID(prevLeaf[:nidSize])
		currentNs := curLeaf[:nidSize]
		// Note that here we would also care for the case current < nId < prevNs
		// but we only allow pushing leaves with ascending namespaces; i.e.
		// prevNs <= currentNs is always true. Also we only check for strictly
		// smaller: prev < nid < current because if we either side was equal, we
		// would have found the namespace before.
		if prevNs.Less(nID) && nID.Less(currentNs) {
			return index
		}
		prevLeaf = curLeaf
	}
	// the case (nID < minNID) or (maxNID < nID) should be handled before
	// calling this private helper!
	panic("calculateAbsenceIndex() called although (nID < minNID) or (maxNID < nID) for provided nID")
}

// foundInRange returns a range of leaves in the namespace tree with the
// namespace IDs that match the given nID. The startIndex and endIndex indicate
// the starting and ending indices of the range, respectively. The endIndex is
// non-inclusive, meaning it does not include the leaf at that index in the
// range. If no leaves are found, foundInRange returns (false, 0, 0).
func (n *NamespacedMerkleTree) foundInRange(nID namespace.ID) (found bool, startIndex int, endIndex int) {
	// This is a faster version of this code snippet:
	// https://github.com/celestiaorg/celestiaorg-prototype/blob/2aeca6f55ad389b9d68034a0a7038f80a8d2982e/simpleblock.go#L106-L117
	foundRng, found := n.namespaceRanges[string(nID)]
	return found, foundRng.Start, foundRng.End
}

// NamespaceSize returns the underlying namespace size. Note that all namespaced
// data is expected to have the same namespace size.
func (n *NamespacedMerkleTree) NamespaceSize() namespace.IDSize {
	return n.treeHasher.NamespaceSize()
}

// Push adds a namespaced data to the tree. The first `n.NamespaceSize()` bytes
// of namespacedData is treated as its namespace ID. Push returns an error if
// the namespaced data is not namespace-prefixed (i.e., its size is smaller than
// the tree's NamespaceSize), or if it is not pushed in ascending order based on
// the namespace ID compared to the previously inserted data (i.e., it is not
// lexicographically sorted by namespace ID).
func (n *NamespacedMerkleTree) Push(namespacedData namespace.PrefixedData) error {
	nID, err := n.validateAndExtractNamespace(namespacedData)
	if err != nil {
		return err
	}
	var (
		res     []byte
		curHash = n.pool.get()
	)
	if n.reuseHasher != nil {
		res, err = n.reuseHasher.HashLeafWithBuffer(namespacedData, curHash)
	} else {
		res, err = n.treeHasher.HashLeaf(namespacedData)
	}
	if err != nil {
		return err
	}
	n.leafHashes = append(n.leafHashes, res)
	n.leaves = append(n.leaves, namespacedData)
	n.updateNamespaceRanges()
	n.updateMinMaxID(nID)
	n.rawRoot = nil
	return nil
}

// Root calculates the namespaced Merkle Tree's root based on the data that has
// been added through the use of the Push method. the returned byte slice is of
// size 2* n.NamespaceSize + the underlying hash output size, and should be
// parsed as minND || maxNID || hash
// Any error returned by this method is irrecoverable and indicate an illegal state of the tree (n).
func (n *NamespacedMerkleTree) Root() ([]byte, error) {
	if n.rawRoot == nil {
		res, err := n.computeRoot(0, n.Size())
		if err != nil {
			return nil, err // this should never happen since leaves are validated in the Push method
		}
		n.rawRoot = res
	}
	return n.rawRoot, nil
}

// FastRoot computes the root of the tree by reusing internal buffers,
// specifically modifying the leafHashes buffer in place. This is more efficient
// than Root() as it avoids allocations, because we reuse all the buffers at each intermediate step
// but it destroys the internal state.
//
// WARNING: After calling this method, the tree becomes unusable for any other
// operations. The leafHashes buffer is consumed and modified during computation.
// This method should only be used when you need to compute the root once and
// then discard the tree.
//
// IMPORTANT: This method currently only works when the number of leaves is a
// power of 2. It will return an error for other sizes.
//
// The returned byte slice is of size 2*n.NamespaceSize + the underlying hash
// output size, and should be parsed as minND || maxNID || hash.
// Any error returned by this method is irrecoverable and indicates an illegal
// state of the tree.
func (n *NamespacedMerkleTree) FastRoot() ([]byte, error) {
	if n.reuseHasher == nil {
		return n.Root()
	}
	if n.rawRoot == nil {
		size := n.Size()
		if size == 0 {
			n.rawRoot = n.treeHasher.EmptyRoot()
			if n.visit != nil {
				n.visit(n.rawRoot)
			}
			return n.rawRoot, nil
		}

		// Check if size is power of 2
		if (size & (size - 1)) != 0 {
			return n.Root()
		}

		// Sequential iterative approach for buffer reuse
		res, err := n.computeRootSequential()
		if err != nil {
			return nil, err
		}
		n.rawRoot = res
	}
	return n.rawRoot, nil
}

// computeRootSequential computes the root using a sequential iterative approach,
// reusing the leafHashes buffer in place. This only works when the number of
// leaves is a power of 2.
func (n *NamespacedMerkleTree) computeRootSequential() ([]byte, error) {
	levelSize := len(n.leafHashes)
	var leftCopy []byte
	if n.visit != nil && levelSize > 0 {
		leftCopy = make([]byte, 0, len(n.leafHashes[0]))
	}

	if levelSize == 1 {
		if n.visit != nil {
			n.visit(n.leafHashes[0], n.leaves[0])
		}
		result := make([]byte, len(n.leafHashes[0]))
		copy(result, n.leafHashes[0])
		n.leafHashes = n.leafHashes[:0]
		return result, nil
	}

	for levelSize > 1 {
		for i := 0; i < levelSize; i += 2 {
			left := n.leafHashes[i]
			right := n.leafHashes[i+1]

			if n.visit != nil && levelSize == len(n.leaves) {
				n.visit(left, n.leaves[i])
				n.visit(right, n.leaves[i+1])
			}
			if n.visit != nil {
				if cap(leftCopy) < len(left) {
					leftCopy = make([]byte, len(left))
				} else {
					leftCopy = leftCopy[:len(left)]
				}
				copy(leftCopy, left)
			}
			res, err := n.reuseHasher.HashNodeReuseLeft(left, right)
			if err != nil {
				return nil, err
			}
			if n.visit != nil {
				n.visit(res, leftCopy, right)
			}
			// we always reuse the left part, so we can put the right part into the pool
			n.pool.put(right)
			n.leafHashes[i/2] = res
		}
		levelSize /= 2
	}
	result := make([]byte, len(n.leafHashes[0]))
	copy(result, n.leafHashes[0])
	n.leafHashes = n.leafHashes[:0]
	return result, nil
}

// MinNamespace returns the minimum namespace ID in this Namespaced Merkle Tree.
// Any errors returned by this method are irrecoverable and indicate an illegal state of the tree (n).
func (n *NamespacedMerkleTree) MinNamespace() (namespace.ID, error) {
	r, err := n.Root()
	if err != nil {
		return nil, err
	}
	return MinNamespace(r, n.NamespaceSize()), nil
}

// MaxNamespace returns the maximum namespace ID in this Namespaced Merkle Tree.
// Any errors returned by this method are irrecoverable and indicate an illegal state of the tree (n).
func (n *NamespacedMerkleTree) MaxNamespace() (namespace.ID, error) {
	r, err := n.Root()
	if err != nil {
		return nil, err
	}
	return MaxNamespace(r, n.NamespaceSize()), nil
}

// ForceAddLeaf adds a namespaced data to the tree without validating its
// namespace ID. This method should only be used by tests that are attempting to
// create out of order trees. The default hasher will fail for trees that are
// out of order.
func (n *NamespacedMerkleTree) ForceAddLeaf(leaf namespace.PrefixedData) error {
	nID := namespace.ID(leaf[:n.NamespaceSize()])
	// compute the leaf hash
	res, err := n.treeHasher.HashLeaf(leaf)
	if err != nil {
		return err
	}

	// update relevant "caches":
	n.leaves = append(n.leaves, leaf)
	n.leafHashes = append(n.leafHashes, res)
	n.updateNamespaceRanges()
	n.updateMinMaxID(nID)
	n.rawRoot = nil
	return nil
}

// computeRoot calculates the namespace Merkle root for a tree/sub-tree that
// encompasses the leaves within the range of [start, end).
// Any errors returned by this method are irrecoverable and indicate an illegal state of the tree (n).
func (n *NamespacedMerkleTree) computeRoot(start, end int) ([]byte, error) {
	// in computeRoot, start may be equal to end which indicates an empty tree hence empty root.
	// Due to this, we need to perform custom range check instead of using validateRange() in which start=end is considered invalid.
	if start < 0 || start > end || end > n.Size() {
		return nil, fmt.Errorf("failed to compute root [%d, %d): %w", start, end, ErrInvalidRange)
	}
	switch end - start {
	case 0:
		rootHash := n.treeHasher.EmptyRoot()
		if n.visit != nil {
			n.visit(rootHash)
		}
		return rootHash, nil
	case 1:
		leafHash := n.leafHashes[start]
		if n.visit != nil {
			n.visit(leafHash, n.leaves[start])
		}
		return leafHash, nil
	default:
		k := getSplitPoint(end - start)
		left, err := n.computeRoot(start, start+k)
		if err != nil { // this should never happen since leaves are added through the Push method, during which leaves formats are validated and their namespace IDs are checked to be sequential.
			return nil, fmt.Errorf("failed to compute subtree root [%d, %d): %w", start, start+k, err)
		}
		right, err := n.computeRoot(start+k, end)
		if err != nil { // this should never happen since leaves are added through the Push method, during which leaves formats are validated and their namespace IDs are checked to be sequential.
			return nil, fmt.Errorf("failed to compute subtree root [%d, %d): %w", start+k, end, err)
		}
		hash, err := n.treeHasher.HashNode(left, right)
		if err != nil { // this error should never happen since leaves are added through the Push method, during which leaves formats are validated and their namespace IDs are checked to be sequential.
			return nil, fmt.Errorf("failed to compute subtree root [%d, %d): %w", left, right, err)
		}
		if n.visit != nil {
			n.visit(hash, left, right)
		}
		return hash, nil
	}
}

// getSplitPoint returns the largest power of 2 less than the length.
// Essentially, it returns the size of the left subtree in a full Merkle tree
// with a total number of leaves equal to length.
func getSplitPoint(length int) int {
	if length < 1 {
		panic("Trying to split a tree with size < 1")
	}
	uLength := uint(length)
	bitlen := bits.Len(uLength)
	k := 1 << (bitlen - 1)
	if k == length {
		k >>= 1
	}
	return k
}

func unsafeBytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(&b[0], len(b))
}

func (n *NamespacedMerkleTree) updateNamespaceRanges() {
	if n.Size() > 0 {
		lastIndex := n.Size() - 1
		lastPushed := n.leaves[lastIndex]
		namespaceSize := n.treeHasher.NamespaceSize()
		// don't allocate memory to copy strings
		lastNs := unsafeBytesToString(lastPushed[:namespaceSize])

		lastRange, found := n.namespaceRanges[lastNs]
		if !found {
			n.namespaceRanges[lastNs] = LeafRange{
				Start: lastIndex,
				End:   lastIndex + 1,
			}
		} else {
			n.namespaceRanges[lastNs] = LeafRange{
				Start: lastRange.Start,
				End:   lastRange.End + 1,
			}
		}
	}
}

// validateAndExtractNamespace verifies whether ndata is a valid namespace
// -prefixed data, and returns its namespace ID. The first `n.NamespaceSize()`
// bytes of namespacedData is treated as its namespace ID.
// validateAndExtractNamespace returns an error if the namespaced data is not
// namespace-prefixed (i.e., its size is smaller than the tree's NamespaceSize),
// or if its namespace ID is smaller than the last leaf data in the tree (i.e.,
// the n.leaves should be sorted in ascending order by their namespace ID).
// validateAndExtractNamespace returns one of the following errors:
// - ErrInvalidLeafLen: indicates the length of the ndata is smaller than the tree's NamespaceSize.
// - ErrInvalidPushOrder: indicates the namespace ID of the ndata is smaller than the last leaf data in the tree.
func (n *NamespacedMerkleTree) validateAndExtractNamespace(ndata namespace.PrefixedData) (namespace.ID, error) {
	nidSize := int(n.NamespaceSize())
	if len(ndata) < nidSize {
		return nil, fmt.Errorf("%w: got: %v, want >= %v", ErrInvalidLeafLen, len(ndata), nidSize)
	}
	nID := namespace.ID(ndata[:n.NamespaceSize()])
	// ensure pushed data doesn't have a smaller namespace than the previous
	// one:
	curSize := n.Size()
	if curSize > 0 {
		if nID.Less(n.leaves[curSize-1][:nidSize]) {
			return nil, fmt.Errorf(
				"%w: last namespace: %x, pushed: %x",
				ErrInvalidPushOrder,
				n.leaves[curSize-1][:nidSize],
				nID,
			)
		}
	}
	return nID, nil
}

func (n *NamespacedMerkleTree) updateMinMaxID(id namespace.ID) {
	if id.Less(n.minNID) {
		n.minNID = id
	}
	if n.maxNID.Less(id) {
		n.maxNID = id
	}
}

// ComputeSubtreeRoot takes a leaf range and returns the corresponding subtree root.
// Also, it requires the start and end range to correctly reference an inner node.
// The provided range, defined by start and end, is end-exclusive.
func (n *NamespacedMerkleTree) ComputeSubtreeRoot(start, end int) ([]byte, error) {
	if start < 0 {
		return nil, fmt.Errorf("start %d shouldn't be strictly negative", start)
	}
	if end <= start {
		return nil, fmt.Errorf("end %d should be stricly bigger than start %d", end, start)
	}
	uStart, err := safeIntToUint(start)
	if err != nil {
		return nil, err
	}
	uEnd, err := safeIntToUint(end)
	if err != nil {
		return nil, err
	}
	// check if the provided range correctly references an inner node.
	// calculates the ideal tree from the provided range, and verifies if it is the same as the range
	if idealTreeRange := nextSubtreeSize(uint64(uStart), uint64(uEnd)); end-start != idealTreeRange {
		return nil, fmt.Errorf("the provided range [%d, %d) does not construct a valid subtree root range", start, end)
	}
	return n.computeRoot(start, end)
}

type LeafRange struct {
	// Start and End denote the indices of a leaf in the tree.
	// Start ranges from 0 up to the total number of leaves minus 1.
	// End ranges from 1 up to the total number of leaves.
	// End is non-inclusive
	Start, End int
}

// MinNamespace extracts the minimum namespace ID from a given namespace hash,
// which is formatted as: minimum namespace ID || maximum namespace ID || hash
// digest.
func MinNamespace(hash []byte, size namespace.IDSize) []byte {
	return hash[:size:size]
}

// MaxNamespace extracts the maximum namespace ID from a given namespace hash,
// which is formatted as: minimum namespace ID || maximum namespace ID || hash
// digest.
func MaxNamespace(hash []byte, size namespace.IDSize) []byte {
	return hash[size : size*2 : size*2]
}

// Size returns the number of leaves in the tree.
func (n *NamespacedMerkleTree) Size() int {
	return len(n.leaves)
}

// Reset clears the tree state while preserving allocated memory for reuse.
// After calling Reset(), the tree can be reused by calling Push() again.
func (n *NamespacedMerkleTree) Reset() [][]byte {
	leaves := n.leaves
	n.leaves = n.leaves[:0]
	n.namespaceRanges = map[string]LeafRange{}
	n.leafHashes = n.leafHashes[:0]
	n.minNID = bytes.Repeat([]byte{0xFF}, int(n.treeHasher.NamespaceSize()))
	n.maxNID = bytes.Repeat([]byte{0x00}, int(n.treeHasher.NamespaceSize()))
	n.rawRoot = nil
	return leaves
}
