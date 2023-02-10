// Package nmt contains an NMT implementation.
package nmt

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"math/bits"

	"github.com/celestiaorg/nmt/namespace"
)

const (
	DefaultNamespaceIDLen = 8
	DefaultCapacity       = 128
)

var (
	ErrInvalidRange            = errors.New("invalid proof range")
	ErrMismatchedNamespaceSize = errors.New("mismatching namespace sizes")
	ErrInvalidPushOrder        = errors.New("pushed data has to be lexicographically ordered by namespace IDs")
	noOp                       = func(hash []byte, children ...[]byte) {}
)

type NodeVisitorFn = func(hash []byte, children ...[]byte)

type Options struct {
	InitialCapacity    int
	NamespaceIDSize    namespace.IDSize
	IgnoreMaxNamespace bool
	NodeVisitor        NodeVisitorFn
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
// Defaults to 8 bytes.
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
// E.g., see: https://github.com/celestiaorg/celestiaorg-specs/blob/master/specs/data_structures.md#namespace-merkle-tree
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

type NamespacedMerkleTree struct {
	treeHasher *Hasher
	visit      NodeVisitorFn

	// just cache stuff until we pass in a store and keep all nodes in there
	// currently, only leaves and leafHashes are stored:
	leaves [][]byte
	// store leaf hashes whenever computed (via Root() or via computeLeafHashesIfNecessary)
	// TODO [Me] we need to check whether leafHashes are not redunduntly
	//  computed
	leafHashes [][]byte

	// this can be used to efficiently look up the range for an
	// existing namespace without iterating through the leaves
	// the map key is the string representation of a namespace.ID  and
	// the leafRange indicates the starting position and ending position of
	// the leaves matching that namespace ID in the tree
	namespaceRanges map[string]leafRange
	minNID          namespace.ID
	maxNID          namespace.ID

	// cache the root
	rawRoot []byte
}

// New initializes a namespaced Merkle tree using the given base hash function
// and for the given namespace size (number of bytes).
// If the namespace size is 0 this corresponds to a regular non-namespaced
// Merkle tree.
// TODO [Me] Why not using a fixed namespace size? i.e., the DefaultNamespaceIDLen, is the variable size for the space efficiency?
func New(h hash.Hash, setters ...Option) *NamespacedMerkleTree {
	// default options:
	opts := &Options{
		InitialCapacity:    DefaultCapacity,
		NamespaceIDSize:    DefaultNamespaceIDLen,
		IgnoreMaxNamespace: true,
		NodeVisitor:        noOp,
	}

	for _, setter := range setters {
		setter(opts)
	}
	treeHasher := NewNmtHasher(h, opts.NamespaceIDSize, opts.IgnoreMaxNamespace)
	return &NamespacedMerkleTree{
		treeHasher:      treeHasher,
		visit:           opts.NodeVisitor,
		leaves:          make([][]byte, 0, opts.InitialCapacity),
		leafHashes:      make([][]byte, 0, opts.InitialCapacity),
		namespaceRanges: make(map[string]leafRange),
		// TODO [Me] Shouldn't minNID be populated by `0x00`?
		minNID: bytes.Repeat([]byte{0xFF}, int(opts.NamespaceIDSize)),
		maxNID: bytes.Repeat([]byte{0x00}, int(opts.NamespaceIDSize)),
	}
}

// Prove leaf at index.
// Note this is not really NMT specific but the tree supports inclusions proofs
// like any vanilla Merkle tree.
// the returned Proof contains the audit path for a leaf at the given index
// Prove is a thin wrapper around the ProveRange and constructs the correct range for the given leaf index
func (n *NamespacedMerkleTree) Prove(index int) (Proof, error) {
	return n.ProveRange(index, index+1)
}

// ProveRange returns the audit path for the supplied range of leaves i.e., [start, end).
func (n *NamespacedMerkleTree) ProveRange(start, end int) (Proof, error) {
	isMaxNsIgnored := n.treeHasher.IsMaxNamespaceIDIgnored()
	n.computeLeafHashesIfNecessary()
	// TODO: store nodes and re-use the hashes instead recomputing parts of the tree here
	if start < 0 || start >= end || end > len(n.leafHashes) {
		return NewEmptyRangeProof(isMaxNsIgnored), ErrInvalidRange
	}
	proof := n.buildRangeProof(start, end)

	return NewInclusionProof(start, end, proof, isMaxNsIgnored), nil
}

// ProveNamespace returns a range proof for the given NamespaceID.
//
// case 1) If the namespace nID is out of the range of the tree's min and max namespace
// i.e., (nID < n.minNID) or (n.maxNID < nID)
//  we do not generate any range proof, instead we return an empty Proof with the range (0,0) i.e.,
// Proof.start = 0 and Proof.end = 0
// to indicate that this namespace is not contained in the tree.
//
// case 2) If the namespace nID is within the range of the tree's min and max namespace
// i.e., n.minNID<= n.ID <=n.maxNID
// and the tree does not have any entries with the given Namespace ID nID,
// this will be proven by returning the inclusion/range Proof of the (namespaced or rather flagged)
// hash of the leaf of the tree with the largest namespace ID that is smaller than nID.
// if there are multiple of such leaves, then the proof is done w.r.t. to the one with the highest index
// the leafHash field of the returned Proof will contain the namespaced hash of such leaf.
//
// case 3) In case the underlying tree contains leaves with the given namespace
// their start and end index will be returned together with a range proof and
// the found leaves. In that case the leafHash field of the returned Proof will be nil.
func (n *NamespacedMerkleTree) ProveNamespace(nID namespace.ID) (Proof, error) {
	isMaxNsIgnored := n.treeHasher.IsMaxNamespaceIDIgnored()
	// case 1)
	// In the cases (n.nID < minNID) or (n.maxNID < nID),
	// return empty range and no proof
	if nID.Less(n.minNID) || n.maxNID.Less(nID) { // TODO [Me] we could move this entire if block inside the `foundInRange` function
		// TODO [Me] Shouldn't we instead return the first or the last node in the tree as the exclusion proof?
		// TODO [Me] although I think this current logic is based on the premise that the root of the tree is trusted
		return NewEmptyRangeProof(isMaxNsIgnored), nil
	}

	// find the range of indices of leaves with the given nID
	found, proofStart, proofEnd := n.foundInRange(nID)

	// case 2)
	if !found {
		// To generate a proof for an absence we calculate the
		// position of the leaf that is in the place of where
		// the namespace would be in:
		proofStart = n.calculateAbsenceIndex(nID) // TODO [Me] this could simply return a range, to avoid the line below
		proofEnd = proofStart + 1
	}

	// case 3)
	// At this point we either found leaves with the namespace nID in the tree or calculated
	// the range it would be in (to generate a proof of absence and to return
	// the corresponding leaf hashes).
	n.computeLeafHashesIfNecessary() // TODO [Me] Why it is needed? cannot we make sure the leaves hashes are calculated as soon as a data is pushed to the tree?
	proof := n.buildRangeProof(proofStart, proofEnd)

	if found {
		return NewInclusionProof(
			proofStart, proofEnd, proof, isMaxNsIgnored
		), nil
	}
	// TODO [Me] the underlying struct type for both inclusion and absence proofs are the same, i.e., `Proof`
	// TODO [Me] the only distinction is in the presence/absence of the `leafHash`,
	// TODO [Me] the interpretation of the `Proof` then may be a bit non-trivial
	// TODO [Me] however, we may want to actually add an extra field to the `Proof`
	// TODO [Me] that indicates whether the proof is for inclusion or for absence

	return NewAbsenceProof(
		proofStart, proofEnd, proof, n.leafHashes[proofStart], isMaxNsIgnored
	), nil
}

// buildRangeProof returns the nodes (as byte slices) in the range proof of the supplied range i.e.,
// [proofStart, proofEnd) where proofEnd is non-inclusive.
// The nodes are ordered according to in order traversal of the namespaced tree. (TODO [Me] I need to double-check the order)
func (n *NamespacedMerkleTree) buildRangeProof(proofStart, proofEnd int) [][]byte {
	// TODO a more secure way would be to make it slice of fixed size arrays i.e., the hash output size
	proof := [][]byte{} // it is the list of nodes hashes (as byte slices) with no index
	var recurse func(start, end int, includeNode bool) []byte

	// start, end are indices of leaves in the tree hence they should be within the size of the tree i.e.,
	// less than or equal to the len(n.leaves)
	// this recursive algorithm is inspired by RFC6962 https://www.rfc-editor.org/rfc/rfc6962#section-2.1
	// includeNode indicates whether the hash of the current subtree (covering the supplied range i.e., [start, end)) or
	// one of its constituent subtrees should be part of the proof
	recurse = func(start, end int, includeNode bool) []byte {
		if start >= len(n.leafHashes) { // TODO [Me] why against leafHashes? and not leaves?
			// TODO [Me] Why there is no check for the end index?
			return nil
		}

		// reached a leaf
		if end-start == 1 {
			leafHash := n.leafHashes[start]
			// if the index of the leaf node is out of the queried range i.e., [proofStart, proofEnd]
			// and if the leaf is required as part of the proof i.e., includeNode == true
			if (start < proofStart || start >= proofEnd) && includeNode {
				// add the leafHash to the proof
				proof = append(proof, leafHash)
			}
			// if the index of the leaf is within the queried range i.e., [proofStart, proofEnd] OR
			// if the leaf is not required as part of the proof i.e., includeNode == false
			return leafHash
		}

		// newIncludeNode indicates whether one of the subtrees of the current subtree [start, end)
		// may have an overlap with the queried proof range i.e., [proofStart, proofEnd)
		newIncludeNode := includeNode
		// check whether the subtree representing the [start, end) range of leaves has overlap with the
		// queried proof range i.e., [proofStart, proofEnd)
		// if not
		if (end <= proofStart || start >= proofEnd) && includeNode { // TODO [Me] the `&& includeNode` seems ineffective and unnecessary
			// setting newIncludeNode to false indicates that non of the subtrees (left and right) of the current
			// subtree are required for the proof
			// because the range of the leaves they cover have no overlap with the
			// queried proof range i.e., [proofStart, proofEnd)
			newIncludeNode = false
		}

		// TODO [Me] Optimization idea: if includeNode is true and [start, end) are within the [proofStart, proofEnd) range, then we do not need to
		// TODO [Me] split further, as neither the current subtree nor any of its left and right subtrees are needed for the proof

		// recursively get left and right subtree
		k := getSplitPoint(end - start)

		left := recurse(start, start+k, newIncludeNode)
		right := recurse(start+k, end, newIncludeNode)

		// only right leaf/subtree can be non-existent
		var hash []byte
		if right == nil {
			hash = left
		} else {
			hash = n.treeHasher.HashNode(left, right)
		}

		// if the hash of the subtree representing [start, end) should be part of the proof but not its left and right subtrees
		if includeNode && !newIncludeNode {
			proof = append(proof, hash)
		}

		return hash
	}

	fullTreeSize := getSplitPoint(len(n.leafHashes)) * 2
	if fullTreeSize < 1 {
		fullTreeSize = 1
	}
	recurse(0, fullTreeSize, true)
	return proof
}

// Get returns leaves for the given namespace.ID.
func (n *NamespacedMerkleTree) Get(nID namespace.ID) [][]byte {
	_, start, end := n.foundInRange(nID)
	return n.leaves[start:end]
}

// GetWithProof is a convenience method returns leaves for the given namespace.ID
// together with the proof for that namespace. It returns the same result
// as calling the combination of Get(nid) and ProveNamespace(nid).
func (n *NamespacedMerkleTree) GetWithProof(nID namespace.ID) (
	[][]byte, Proof, error
) {
	data := n.Get(nID)
	proof, err := n.ProveNamespace(nID)
	return data, proof, err
}

// calculateAbsenceIndex returns the index of a leaf with the largest namespace ID which is smaller than nID
// in case there are multiple leaves with this property, then the index of the highest one
// is returned
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

// foundInRange returns true, together with the starting index and ending index of a range of leaves in the namespace tree whose namespace IDs match the given nID.
// if no leaves is found, foundInRange returns (false, 0, 0).
// the ending index is non-inclusive
func (n *NamespacedMerkleTree) foundInRange(nID namespace.ID) (bool, int, int) {
	// This is a faster version of this code snippet:
	// https://github.com/celestiaorg/celestiaorg-prototype/blob/2aeca6f55ad389b9d68034a0a7038f80a8d2982e/simpleblock.go#L106-L117
	foundRng, found := n.namespaceRanges[string(nID)]
	// XXX casting from uint64 to int is kinda crappy but nebolousLabs'
	// range proof api requires int params only to convert them to uint64 ...
	return found, int(foundRng.start), int(foundRng.end)
}

// NamespaceSize returns the underlying namespace size. Note that
// all namespaced data is expected to have the same namespace size.
func (n *NamespacedMerkleTree) NamespaceSize() namespace.IDSize {
	return n.treeHasher.NamespaceSize()
}

// Push adds data with the corresponding namespace ID to the tree.
// Returns an error if the namespace ID size of the input
// does not match the tree's NamespaceSize() or the leaves are not pushed in
// order (i.e. lexicographically sorted by namespace ID).
func (n *NamespacedMerkleTree) Push(namespacedData namespace.PrefixedData) error {
	nID, err := n.validateAndExtractNamespace(namespacedData)
	if err != nil {
		return err
	}

	// update relevant "caches":
	n.leaves = append(n.leaves, namespacedData)
	// TODO [Me] why not calculating the hash right away and add it to n.leafHashes
	n.updateNamespaceRanges()
	n.updateMinMaxID(nID)
	n.rawRoot = nil
	return nil
}

// Root returns the namespaced Merkle Tree's root with the minimum and maximum
// namespace. min || max || hashDigest
func (n *NamespacedMerkleTree) Root() []byte {
	if n.rawRoot == nil {
		n.rawRoot = n.computeRoot(0, len(n.leaves))
	}
	return n.rawRoot
}

func (n *NamespacedMerkleTree) computeRoot(start, end int) []byte {
	switch end - start {
	case 0:
		rootHash := n.treeHasher.EmptyRoot()
		n.visit(rootHash)
		return rootHash
	case 1:
		leafHash := n.treeHasher.HashLeaf(n.leaves[start])
		// TODO [Me] how do we know which leaves are already hashed and
		//  inserted into n.leafHashes? it might be the case that the tree
		//  has 10 leaves, but we run computeRoot(0,1) for 10 times,
		//  hence the leafHashes gets populated by the hash of the first leaf
		//  only. I think leaves should be hashed as soon as they get
		//  inserted to the tree via Push method.
		if len(n.leafHashes) < len(n.leaves) {
			n.leafHashes = append(n.leafHashes, leafHash)
		}
		n.visit(leafHash, n.leaves[start])
		return leafHash
	default:
		k := getSplitPoint(end - start)
		left := n.computeRoot(start, start+k)
		right := n.computeRoot(start+k, end)
		hash := n.treeHasher.HashNode(left, right)
		n.visit(hash, left, right)
		return hash
	}
}

// getSplitPoint returns the largest power of 2 less than the length
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

func (n *NamespacedMerkleTree) validateAndExtractNamespace(ndata namespace.PrefixedData) (
	namespace.ID, error
) {
	nidSize := int(n.NamespaceSize())
	if len(ndata) < nidSize {
		return nil, fmt.Errorf(
			"%w: got: %v, want >= %v", ErrMismatchedNamespaceSize, len(ndata),
			nidSize
		)
	}
	nID := namespace.ID(ndata[:n.NamespaceSize()])
	// ensure pushed data doesn't have a smaller namespace than the previous one:
	curSize := len(n.leaves)
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

// computes the leaf hashes if not already done in a previous call
// of NamespacedMerkleTree.Root()
func (n *NamespacedMerkleTree) computeLeafHashesIfNecessary() {
	// check whether all the hash of all the existing leaves are available
	if len(n.leafHashes) < len(n.leaves) {
		n.leafHashes = make([][]byte, len(n.leaves))
		for i, leaf := range n.leaves {
			n.leafHashes[i] = n.treeHasher.HashLeaf(leaf)
		}
	}
}

type leafRange struct {
	start, end uint64
}

// MinNamespace parses the minimum namespace id from a given hash
func MinNamespace(hash []byte, size namespace.IDSize) []byte {
	min := make([]byte, 0, size)
	return append(min, hash[:size]...)
}

// MaxNamespace parses the maximum namespace id from a given hash
func MaxNamespace(hash []byte, size namespace.IDSize) []byte {
	max := make([]byte, 0, size)
	return append(max, hash[size:size*2]...)
}