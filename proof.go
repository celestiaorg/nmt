package nmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/bits"
	"slices"

	"github.com/celestiaorg/nmt/namespace"
	"github.com/celestiaorg/nmt/pb"
)

var (
	// ErrFailedCompletenessCheck indicates that the verification of a namespace proof failed due to the lack of completeness property.
	ErrFailedCompletenessCheck = errors.New("failed completeness check")
	ErrWrongLeafHashesSize     = errors.New("wrong leafHashes size")
)

// Proof represents a namespace proof of a namespace.ID in an NMT. In case this
// proof proves the absence of a namespace.ID in a tree it also contains the
// leaf hashes of the range where that namespace would be.
type Proof struct {
	// start index of the leaves that match the queried namespace.ID.
	start int
	// end index (non-inclusive) of the leaves that match the queried
	// namespace.ID.
	end int
	// nodes hold the tree nodes necessary for the Merkle range proof of
	// `[start, end)` in the order of an in-order traversal of the tree. in
	// specific, nodes contain: 1) the namespaced hash of the left siblings for
	// the Merkle inclusion proof of the `start` leaf 2) the namespaced hash of
	// the right siblings of the Merkle inclusion proof of  the `end` leaf
	nodes [][]byte
	// leafHash are nil if the namespace is present in the NMT. In case the
	// namespace to be proved is in the min/max range of the tree but absent,
	// this will contain the leaf hash necessary to verify the proof of absence.
	// leafHash contains a tree leaf that 1) its namespace ID is the smallest
	// namespace ID larger than nid and 2) the namespace ID of the leaf to the
	// left of it is smaller than the nid.
	leafHash []byte
	// isMaxNamespaceIDIgnored is set to true if the tree from which this Proof
	// was generated from is initialized with Options.IgnoreMaxNamespace ==
	// true. The IgnoreMaxNamespace flag influences the calculation of the
	// namespace ID range for intermediate nodes in the tree. This flag signals
	// that, when determining the upper limit of the namespace ID range for a
	// tree node, the maximum possible namespace ID (equivalent to
	// "NamespaceIDSize" bytes of 0xFF, or 2^NamespaceIDSize-1) should be
	// omitted if feasible. For a more in-depth understanding of this field,
	// refer to the "HashNode" method in the "Hasher.
	isMaxNamespaceIDIgnored bool
}

func (proof Proof) MarshalJSON() ([]byte, error) {
	pbProofObj := pb.Proof{
		Start:                 int64(proof.start),
		End:                   int64(proof.end),
		Nodes:                 proof.nodes,
		LeafHash:              proof.leafHash,
		IsMaxNamespaceIgnored: proof.isMaxNamespaceIDIgnored,
	}
	return json.Marshal(pbProofObj)
}

func (proof *Proof) UnmarshalJSON(data []byte) error {
	var pbProof pb.Proof
	err := json.Unmarshal(data, &pbProof)
	if err != nil {
		return err
	}
	proof.start = int(pbProof.Start)
	proof.end = int(pbProof.End)
	proof.nodes = pbProof.Nodes
	proof.leafHash = pbProof.LeafHash
	proof.isMaxNamespaceIDIgnored = pbProof.IsMaxNamespaceIgnored
	return nil
}

// Start index of this proof.
func (proof Proof) Start() int {
	return proof.start
}

// End index of this proof, non-inclusive.
func (proof Proof) End() int {
	return proof.end
}

// Nodes return the proof nodes that together with the corresponding leaf values
// can be used to recompute the root and verify this proof.
func (proof Proof) Nodes() [][]byte {
	return proof.nodes
}

// IsOfAbsence returns true if this proof proves the absence of leaves of a
// namespace in the tree.
func (proof Proof) IsOfAbsence() bool {
	return len(proof.leafHash) > 0
}

// LeafHash returns nil if the namespace has leaves in the NMT. In case the
// namespace.ID to be proved is in the min/max range of the tree but absent,
// this will contain the leaf hash necessary to verify the proof of absence.
func (proof Proof) LeafHash() []byte {
	return proof.leafHash
}

// IsNonEmptyRange returns true if this proof contains a valid, non-empty proof
// range.
func (proof Proof) IsNonEmptyRange() bool {
	return proof.start >= 0 && proof.start < proof.end
}

// IsMaxNamespaceIDIgnored returns true if the proof has been created under the ignore max namespace logic.
// see ./docs/nmt-lib.md for more details.
func (proof Proof) IsMaxNamespaceIDIgnored() bool {
	return proof.isMaxNamespaceIDIgnored
}

// NewEmptyRangeProof constructs a proof that proves that a namespace.ID does
// not fall within the range of an NMT.
func NewEmptyRangeProof(ignoreMaxNamespace bool) Proof {
	return Proof{0, 0, nil, nil, ignoreMaxNamespace}
}

// NewInclusionProof constructs a proof that proves that a namespace.ID is
// included in an NMT.
func NewInclusionProof(proofStart, proofEnd int, proofNodes [][]byte, ignoreMaxNamespace bool) Proof {
	return Proof{proofStart, proofEnd, proofNodes, nil, ignoreMaxNamespace}
}

// NewAbsenceProof constructs a proof that proves that a namespace.ID falls
// within the range of an NMT but no leaf with that namespace.ID is included.
func NewAbsenceProof(proofStart, proofEnd int, proofNodes [][]byte, leafHash []byte, ignoreMaxNamespace bool) Proof {
	return Proof{proofStart, proofEnd, proofNodes, leafHash, ignoreMaxNamespace}
}

// IsEmptyProof checks whether the proof corresponds to an empty proof as defined in NMT specifications https://github.com/celestiaorg/nmt/blob/main/docs/spec/nmt.md.
func (proof Proof) IsEmptyProof() bool {
	return proof.start == proof.end && len(proof.nodes) == 0 && len(proof.leafHash) == 0
}

func (proof Proof) isValidEmptyRangeProof(nth *NmtHasher, nID namespace.ID, root []byte, leaves [][]byte, checkNS bool) bool {
	if !proof.IsEmptyProof() || len(leaves) != 0 {
		return false
	}

	if !checkNS {
		return true
	}

	nIDLen := nID.Size()
	rootMin := namespace.ID(MinNamespace(root, nIDLen))
	rootMax := namespace.ID(MaxNamespace(root, nIDLen))

	// empty proofs are always rejected unless 1) nID is outside the range of
	// namespaces covered by the root 2) the root represents an empty tree, since
	// it purports to cover the zero namespace but does not actually include
	// any such nodes
	return nID.Less(rootMin) || rootMax.Less(nID) || bytes.Equal(root, nth.EmptyRoot())
}

// ComputeAndValidateLeafHashes validates and hashes a list of leaves using the provided NMT hasher.
func ComputeAndValidateLeafHashes(nth *NmtHasher, nid namespace.ID, leaves [][]byte) ([][]byte, error) {
	hashes := make([][]byte, len(leaves))
	for i, leaf := range leaves {
		if nth.ValidateLeaf(leaf) != nil {
			return nil, fmt.Errorf("invalid leaf data: does not contain the expected namespace prefix")
		}
		// check whether the namespace ID of the data matches the queried nID
		if leafNid := namespace.ID(leaf[:nid.Size()]); !leafNid.Equal(nid) {
			// conflicting namespace IDs in data
			return nil, fmt.Errorf("leaf with namespace ID %x does not belong to expected namespace %x", leafNid, nid)
		}
		hash, err := nth.HashLeaf(leaf)
		if err != nil {
			return nil, fmt.Errorf("failed to hash leaf: %w", err)
		}
		hashes[i] = hash
	}
	return hashes, nil
}

// ComputePrefixedLeafHashes computes NMT leaf hashes for raw leaf data by prepending the given namespace ID.
func ComputePrefixedLeafHashes(nth *NmtHasher, nid namespace.ID, leaves [][]byte) ([][]byte, error) {
	hashes := make([][]byte, len(leaves))
	for i, leaf := range leaves {
		// prepend the namespace to the leaf data and hash it
		hash, err := nth.HashLeaf(slices.Concat(nid, leaf))
		if err != nil {
			return nil, err
		}
		hashes[i] = hash
	}
	return hashes, nil
}

// VerifyNamespace verifies a whole namespace, i.e. 1) it verifies inclusion of
// the provided `leaves` in the tree (or the proof.leafHash in case of
// full/short absence proof) 2) it verifies that the namespace is complete
// i.e., the data items matching the namespace `nID`  are within the range
// [`proof.start`, `proof.end`) and no data of that namespace was left out.
// VerifyNamespace deems an empty `proof` valid if the queried `nID` falls
// outside the namespace  range of the supplied `root` or if the `root` is empty
//
// `h` MUST be the same as the underlying hash function used to generate the
// proof. Otherwise, the verification will fail. `nID` is the namespace ID for
// which the namespace `proof` is generated. `leaves` contains the namespaced
// leaves of the tree in the range of [`proof.start`, `proof.end`).
// For an absence `proof`, the `leaves` is empty.
// `leaves` items MUST be ordered according to their index in the tree,
// with `leaves[0]` corresponding to the namespaced leaf at index `start`,
// and the last element in `leaves` corresponding to the leaf at index `end-1`
// of the tree.
//
// `root` is the root of the NMT against which the `proof` is verified.
func (proof Proof) VerifyNamespace(h hash.Hash, nID namespace.ID, leaves [][]byte, root []byte) bool {
	nIDLen := nID.Size()
	nth := NewNmtHasher(h, nIDLen, proof.isMaxNamespaceIDIgnored)

	// if empty range proof, check that the proof is valid
	if proof.start == proof.end {
		return proof.isValidEmptyRangeProof(nth, nID, root, leaves, true)
	}

	gotLeafHashes := make([][]byte, 0, len(leaves))
	if proof.IsOfAbsence() {
		gotLeafHashes = append(gotLeafHashes, proof.leafHash)
	} else {
		var err error
		gotLeafHashes, err = ComputeAndValidateLeafHashes(nth, nID, leaves)
		if err != nil {
			return false
		}
	}

	// with verifyCompleteness set to true:
	res, err := proof.VerifyLeafHashes(nth, true, nID, gotLeafHashes, root)
	if err != nil {
		return false
	}
	return res
}

// ValidateProofStructure checks ranges, leaf and node formats, and input compatibility.
func (proof Proof) ValidateProofStructure(nth *NmtHasher, nID namespace.ID, leafHashes [][]byte) error {
	// check that the proof range is valid
	if proof.Start() < 0 || proof.Start() >= proof.End() {
		return fmt.Errorf("proof range [proof.start=%d, proof.end=%d) is not valid: %w", proof.Start(), proof.End(), ErrInvalidRange)
	}

	// check whether the number of leaves match the proof range i.e., end-start.
	// If not, make an early return.
	expectedLeafHashesCount := proof.End() - proof.Start()
	if len(leafHashes) != expectedLeafHashesCount {
		return fmt.Errorf("supplied leafHashes size %d, expected size %d: %w", len(leafHashes), expectedLeafHashesCount, ErrWrongLeafHashesSize)
	}

	// if the proof is an absence proof,
	// the leafHash must be valid w.r.t the NMT hasher and queried namespace ID
	if proof.IsOfAbsence() {
		if err := nth.ValidateNodeFormat(proof.leafHash); err != nil {
			return fmt.Errorf("leaf hash does not match the NMT hasher's hash format: %w", err)
		}
		// conduct some sanity checks:
		leafMinNID := namespace.ID(proof.leafHash[:nID.Size()])
		if !nID.Less(leafMinNID) {
			// leafHash.minNID  must be greater than nID
			return fmt.Errorf("leaf hash %x does not belong to namespace %x", proof.leafHash, nID)
		}
	}

	// check that namespace ID size matches the NMT hasher's namespace size
	if nID.Size() != nth.NamespaceSize() {
		return fmt.Errorf("namespace ID size (%d) does not match the namespace size of the NMT hasher (%d)", nID.Size(), nth.NamespaceSize())
	}

	// check that all the proof.nodes are valid w.r.t the NMT hasher
	for _, node := range proof.nodes {
		if err := nth.ValidateNodeFormat(node); err != nil {
			return fmt.Errorf("proof nodes do not match the NMT hasher's hash format: %w", err)
		}
	}

	// check that all the leafHashes are valid w.r.t the NMT hasher
	for _, leafHash := range leafHashes {
		if err := nth.ValidateNodeFormat(leafHash); err != nil {
			return fmt.Errorf("leaf hash does not match the NMT hasher's hash format: %w", err)
		}
	}

	return nil
}

// ValidateNamespace ensures all leaf hashes belong to the expected namespace.
func (proof Proof) ValidateNamespace(nth *NmtHasher, nID namespace.ID, leafHashes [][]byte) error {
	for _, leafHash := range leafHashes {
		minNsID := MinNamespace(leafHash, nth.NamespaceSize())
		maxNsID := MaxNamespace(leafHash, nth.NamespaceSize())
		if !nID.Equal(minNsID) || !nID.Equal(maxNsID) {
			return fmt.Errorf("leaf hash %x does not belong to namespace %x", leafHash, nID)
		}
	}
	return nil
}

// ValidateCompleteness checks whether a namespace proof is complete for the given namespace ID.
func (proof Proof) ValidateCompleteness(nth *NmtHasher, nID namespace.ID) error {
	var leafIndex uint64
	// leftSubtrees is to be populated by the subtree roots upto [0, r.Start)
	leftSubtrees := make([][]byte, 0, len(proof.nodes))

	nodes := proof.nodes
	for leafIndex != uint64(proof.Start()) && len(nodes) > 0 {
		subtreeSize := nextSubtreeSize(leafIndex, uint64(proof.Start()))
		leftSubtrees = append(leftSubtrees, nodes[0])
		nodes = nodes[1:]
		leafIndex += uint64(subtreeSize)
	}
	// rightSubtrees only contains the subtrees after r.End
	rightSubtrees := nodes

	// leftSubtrees contains the subtree roots upto [0, r.Start)
	for _, subtree := range leftSubtrees {
		leftSubTreeMax := MaxNamespace(subtree, nth.NamespaceSize())
		if nID.LessOrEqual(namespace.ID(leftSubTreeMax)) {
			return ErrFailedCompletenessCheck
		}
	}
	for _, subtree := range rightSubtrees {
		rightSubTreeMin := MinNamespace(subtree, nth.NamespaceSize())
		if namespace.ID(rightSubTreeMin).LessOrEqual(nID) {
			return ErrFailedCompletenessCheck
		}
	}
	return nil
}

// ComputeRootWithBasicValidation computes the Merkle root from a given proof and a set of leaf hashes,
// performing basic validation steps prior to computing the root.
//
// If isNamespace is true, it additionally validates:
//   - That the leaf hashes belong to the specified namespace.
//   - That the proof is complete for the given namespace.
//
// Parameters:
//   - nth: The NMT hasher instance used for validation and root computation.
//   - nID: The namespace ID that the proof is expected to correspond to.
//   - leafHashes: The hashes of the leaves being proven.
//   - isNamespace: A flag indicating whether namespace-specific validation should be performed.
//
// Returns:
//   - The computed root hash if all checks pass.
//   - An error if any validation fails or root computation fails.
func (proof Proof) ComputeRootWithBasicValidation(nth *NmtHasher, nID namespace.ID, leafHashes [][]byte, isNamespace bool) ([]byte, error) {
	if err := proof.ValidateProofStructure(nth, nID, leafHashes); err != nil {
		return nil, err
	}

	if isNamespace {
		if err := proof.ValidateNamespace(nth, nID, leafHashes); err != nil {
			return nil, fmt.Errorf("failed namespace check: %w", err)
		}
		if err := proof.ValidateCompleteness(nth, nID); err != nil {
			return nil, fmt.Errorf("failed completeness check: %w", err)
		}
	}

	rootHash, err := proof.ComputeRoot(nth, leafHashes)
	if err != nil {
		return nil, fmt.Errorf("failed to compute root: %w", err)
	}

	if err := nth.ValidateNodeFormat(rootHash); err != nil {
		return nil, fmt.Errorf("root does not match the NMT hasher's hash format: %w", err)
	}

	return rootHash, nil
}

// ComputeRoot reconstructs the Merkle root from a given proof and a set of leaf hashes.
// It recursively computes the root hash by combining leaf nodes and proof nodes using the NMT hasher.
//
// This function is typically used to verify whether a subset of leaves belongs to a Merkle tree
// by recomputing the root hash and comparing it to a known root.
//
// Parameters:
// - nth: The Namespaced Merkle Tree (NMT) hasher used for hashing nodes.
// - leafHashes: A slice of byte slices representing the leaf hashes that are part of the proof.
//
// Returns:
// - []byte: The computed Merkle root hash.
// - error: An error if the computation fails due to invalid proof structure or hashing issues.
func (proof Proof) ComputeRoot(nth *NmtHasher, leafHashes [][]byte) ([]byte, error) {
	var computeRoot func(start, end int) ([]byte, error)
	// computeRoot can return error iff the HashNode function fails while calculating the root
	computeRoot = func(start, end int) ([]byte, error) {
		// reached a leaf
		if end-start == 1 {
			// if the leaf index falls within the proof range, pop and return a
			// leaf
			if start >= proof.Start() && start < proof.End() {
				// advance leafHashes
				return popIfNonEmpty(&leafHashes), nil
			}

			// if the leaf index  is outside the proof range, pop and return a
			// proof node (which in this case is a leaf) if present, else return
			// nil because leaf doesn't exist
			return popIfNonEmpty(&proof.nodes), nil
		}

		// if current range does not overlap with the proof range, pop and
		// return a proof node if present, else return nil because subtree
		// doesn't exist
		if end <= proof.Start() || start >= proof.End() {
			return popIfNonEmpty(&proof.nodes), nil
		}

		// Recursively get left and right subtree
		k := getSplitPoint(end - start)
		left, err := computeRoot(start, start+k)
		if err != nil {
			return nil, fmt.Errorf("failed to compute subtree root [%d, %d): %w", start, start+k, err)
		}
		right, err := computeRoot(start+k, end)
		if err != nil {
			return nil, fmt.Errorf("failed to compute subtree root [%d, %d): %w", start+k, end, err)
		}

		// only right leaf/subtree can be non-existent
		if right == nil {
			return left, nil
		}
		hash, err := nth.HashNode(left, right)
		if err != nil {
			return nil, fmt.Errorf("failed to hash node: %w", err)
		}
		return hash, nil
	}

	// estimate the leaf size of the subtree containing the proof range
	proofRangeSubtreeEstimate := max(getSplitPoint(proof.end)*2, 1)
	rootHash, err := computeRoot(0, proofRangeSubtreeEstimate)
	if err != nil {
		return nil, fmt.Errorf("failed to compute root [%d, %d): %w", 0, proofRangeSubtreeEstimate, err)
	}
	for _, node := range proof.nodes {
		rootHash, err = nth.HashNode(rootHash, node)
		if err != nil {
			return nil, fmt.Errorf("failed to hash node: %w", err)
		}
	}
	return rootHash, nil
}

// The VerifyLeafHashes function checks whether the given proof is a valid Merkle
// range proof for the leaves in the leafHashes input. It returns true or false accordingly.
// If there is an issue during the proof verification e.g., a node does not conform to the namespace hash format, then a proper error is returned to indicate the root cause of the issue.
// The leafHashes parameter is a list of leaf hashes, where each leaf hash is represented
// by a byte slice.
// The size of leafHashes should match the proof range i.e., end-start.
// If the verifyCompleteness parameter is set to true, the function also checks
// the completeness of the proof by verifying that there is no leaf in the
// tree represented by the root parameter that matches the namespace ID nID
// outside the leafHashes list.
func (proof Proof) VerifyLeafHashes(nth *NmtHasher, verifyCompleteness bool, nID namespace.ID, leafHashes [][]byte, root []byte) (bool, error) {
	if err := proof.ValidateProofStructure(nth, nID, leafHashes); err != nil {
		return false, err
	}

	// check that the root is valid w.r.t the NMT hasher
	if err := nth.ValidateNodeFormat(root); err != nil {
		return false, fmt.Errorf("root does not match the NMT hasher's hash format: %w", err)
	}

	// check that the namespace of leafHashes is the same as the queried namespace, except for the case of absence proof
	if !proof.IsOfAbsence() { // in case of absence proof, the leafHash is the hash of a leaf next to the queried namespace, hence its namespace ID is not the same as the queried namespace ID
		// check the namespace of all the leaf hashes to be the same as the queried namespace
		if err := proof.ValidateNamespace(nth, nID, leafHashes); err != nil {
			return false, err
		}
	}

	if verifyCompleteness {
		if err := proof.ValidateCompleteness(nth, nID); err != nil {
			return false, err
		}
	}

	rootHash, err := proof.ComputeRoot(nth, leafHashes)
	if err != nil {
		return false, err
	}
	return bytes.Equal(rootHash, root), nil
}

// VerifyInclusion checks that the inclusion proof is valid by using leaf data
// and the provided proof to regenerate and compare the root. Note that the leavesWithoutNamespace data should not contain the prefixed namespace, unlike the tree.Push method,
// which takes prefixed data. All leaves implicitly have the same namespace ID:
// `nid`.
// The size of the leavesWithoutNamespace should be equal to the proof range i.e., end-start.
// VerifyInclusion does not verify the completeness of the proof, so it's possible for leavesWithoutNamespace to be a subset of the leaves in the tree that have the namespace ID nid.
func (proof Proof) VerifyInclusion(h hash.Hash, nid namespace.ID, leavesWithoutNamespace [][]byte, root []byte) bool {
	nth := NewNmtHasher(h, nid.Size(), proof.isMaxNamespaceIDIgnored)

	// validate empty proof range
	if proof.start == proof.end {
		return proof.isValidEmptyRangeProof(nth, nid, root, leavesWithoutNamespace, false)
	}

	// add namespace to all the leaves
	hashes, err := ComputePrefixedLeafHashes(nth, nid, leavesWithoutNamespace)
	if err != nil {
		return false
	}

	res, err := proof.VerifyLeafHashes(nth, false, nid, hashes, root)
	if err != nil {
		return false
	}
	return res
}

// VerifySubtreeRootInclusion verifies that a set of subtree roots is included in
// an NMT.
// Warning: This method is Celestia specific! Using it without verifying
// the following assumptions, can return unexpected errors, false positive/negatives:
// - The subtree roots are created according to the ADR-013
// https://github.com/celestiaorg/celestia-app/blob/main/docs/architecture/adr-013-non-interactive-default-rules-for-zero-padding.md
// - The tree's number of leaves is a power of two
// The subtreeWidth is also defined in ADR-013.
// More information on the algorithm used can be found in the ToLeafRanges() method docs.
func (proof Proof) VerifySubtreeRootInclusion(nth *NmtHasher, subtreeRoots [][]byte, subtreeWidth int, root []byte) (bool, error) {
	// check that the proof range is valid
	if proof.Start() < 0 || proof.Start() >= proof.End() {
		return false, fmt.Errorf("proof range [proof.start=%d, proof.end=%d) is not valid: %w", proof.Start(), proof.End(), ErrInvalidRange)
	}

	// check that the root is valid w.r.t the NMT hasher
	if err := nth.ValidateNodeFormat(root); err != nil {
		return false, fmt.Errorf("root does not match the NMT hasher's hash format: %w", err)
	}
	// check that all the proof.Notes() are valid w.r.t the NMT hasher
	for _, node := range proof.Nodes() {
		if err := nth.ValidateNodeFormat(node); err != nil {
			return false, fmt.Errorf("proof nodes do not match the NMT hasher's hash format: %w", err)
		}
	}
	// check that all the subtree roots are valid w.r.t the NMT hasher
	for _, subtreeRoot := range subtreeRoots {
		if err := nth.ValidateNodeFormat(subtreeRoot); err != nil {
			return false, fmt.Errorf("inner nodes does not match the NMT hasher's hash format: %w", err)
		}
	}

	// get the subtree roots leaf ranges
	ranges, err := ToLeafRanges(proof.Start(), proof.End(), subtreeWidth)
	if err != nil {
		return false, err
	}

	// check whether the number of ranges matches the number of subtree roots.
	// if not, make an early return.
	if len(subtreeRoots) != len(ranges) {
		return false, fmt.Errorf("number of subtree roots %d is different than the number of the expected leaf ranges %d", len(subtreeRoots), len(ranges))
	}

	var computeRoot func(start, end int) ([]byte, error)
	// computeRoot can return error iff the HashNode function fails while calculating the root
	computeRoot = func(start, end int) ([]byte, error) {
		// if the current range does not overlap with the proof range, pop and
		// return a proof node if present, else return nil because subtree
		// doesn't exist
		if end <= proof.Start() || start >= proof.End() {
			return popIfNonEmpty(&proof.nodes), nil
		}

		if len(ranges) == 0 {
			return nil, fmt.Errorf("expected to have a subtree root for range [%d, %d)", start, end)
		}

		if ranges[0].Start == start && ranges[0].End == end {
			ranges = ranges[1:]
			return popIfNonEmpty(&subtreeRoots), nil
		}

		if end-start == 1 {
			// At this level, we reached a leaf, but we couldn't find any range corresponding
			// to needed leaf [start, end).
			// This means that the initial provided [start, end) range was invalid.
			return nil, fmt.Errorf("the provided range [%d, %d) does not reference a valid inner node", proof.start, proof.end)
		}

		// Recursively get left and right subtree
		k := getSplitPoint(end - start)
		left, err := computeRoot(start, start+k)
		if err != nil {
			return nil, fmt.Errorf("failed to compute subtree root [%d, %d): %w", start, start+k, err)
		}
		right, err := computeRoot(start+k, end)
		if err != nil {
			return nil, fmt.Errorf("failed to compute subtree root [%d, %d): %w", start+k, end, err)
		}

		// only right leaf/subtree can be non-existent
		if right == nil {
			return left, nil
		}
		hash, err := nth.HashNode(left, right)
		if err != nil {
			return nil, fmt.Errorf("failed to hash node: %w", err)
		}
		return hash, nil
	}

	// estimate the leaf size of the subtree containing the proof range
	proofRangeSubtreeEstimate := getSplitPoint(proof.End()) * 2
	if proofRangeSubtreeEstimate < 1 {
		proofRangeSubtreeEstimate = 1
	}
	rootHash, err := computeRoot(0, proofRangeSubtreeEstimate)
	if err != nil {
		return false, fmt.Errorf("failed to compute root [%d, %d): %w", 0, proofRangeSubtreeEstimate, err)
	}
	for i := 0; i < len(proof.Nodes()); i++ {
		rootHash, err = nth.HashNode(rootHash, proof.Nodes()[i])
		if err != nil {
			return false, fmt.Errorf("failed to hash node: %w", err)
		}
	}

	return bytes.Equal(rootHash, root), nil
}

// ToLeafRanges returns the leaf ranges corresponding to the provided subtree roots.
// The proof range defined by proofStart and proofEnd is end exclusive.
// It uses the subtree root width to calculate the maximum number of leaves a subtree root can
// commit to.
// The subtree root width is defined as per ADR-013:
// https://github.com/celestiaorg/celestia-app/blob/main/docs/architecture/adr-013-non-interactive-default-rules-for-zero-padding.md
// This method assumes:
// - The subtree roots are created according to the ADR-013 non-interactive defaults rules
// - The tree's number of leaves is a power of two
// The algorithm is as follows:
// - Let `d` be `y - x` (the range of the proof).
// - `i` is the index of the next subtree root.
// - While `d != 0`:
//   - Let `z` be the largest power of 2 that fits in `d`; here we are finding the range for the next subtree root.
//   - The range for the next subtree root is `[x, x + z)`, i.e., `S_i` is the subtree root of leaves at indices `[x, x + z)`.
//   - `d = d - z` (move past the first subtree root and its range).
//   - `i = i + 1`.
//   - Go back to the loop condition.
//
// Note: This method is Celestia specific.
func ToLeafRanges(proofStart, proofEnd, subtreeWidth int) ([]LeafRange, error) {
	if proofStart < 0 {
		return nil, fmt.Errorf("proof start %d shouldn't be strictly negative", proofStart)
	}
	if proofEnd <= proofStart {
		return nil, fmt.Errorf("proof end %d should be stricly bigger than proof start %d", proofEnd, proofStart)
	}
	if subtreeWidth <= 0 {
		return nil, fmt.Errorf("subtree root width cannot be negative %d", subtreeWidth)
	}
	currentStart := proofStart
	currentLeafRange := proofEnd - proofStart
	var ranges []LeafRange
	maximumLeafRange := subtreeWidth
	for currentLeafRange != 0 {
		nextRange, err := nextLeafRange(currentStart, proofEnd, maximumLeafRange)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, nextRange)
		currentStart = nextRange.End
		currentLeafRange = currentLeafRange - nextRange.End + nextRange.Start
	}
	return ranges, nil
}

// nextLeafRange takes a proof start, proof end, and the maximum range a subtree
// root can cover, and returns the corresponding subtree root range.
// Check ToLeafRanges() for more information on the algorithm used.
// The subtreeWidth is calculated using SubTreeWidth() method
// in celestiaorg/go-square/inclusion package.
// The subtreeWidth is a power of two.
// Also, the LeafRange values, i.e., the range size, are all powers of two.
// Note: This method is Celestia specific.
func nextLeafRange(currentStart, currentEnd, subtreeWidth int) (LeafRange, error) {
	currentLeafRange := currentEnd - currentStart
	minimum := min(currentLeafRange, subtreeWidth)
	uMinimum, err := safeIntToUint(minimum)
	if err != nil {
		return LeafRange{}, fmt.Errorf("failed to convert subtree root range to Uint %w", err)
	}
	currentRange, err := largestPowerOfTwo(uMinimum)
	if err != nil {
		return LeafRange{}, err
	}
	rangeEnd := currentStart + currentRange
	idealTreeSize := nextSubtreeSize(uint64(currentStart), uint64(rangeEnd))
	if currentStart+idealTreeSize != rangeEnd {
		// this will happen if the calculated range does not correctly reference an inner node in the tree.
		return LeafRange{}, fmt.Errorf("provided subtree width %d doesn't allow creating a valid leaf range [%d, %d)", subtreeWidth, currentStart, rangeEnd)
	}
	return LeafRange{Start: currentStart, End: rangeEnd}, nil
}

// largestPowerOfTwo calculates the largest power of two
// that is smaller than 'bound'
func largestPowerOfTwo(bound uint) (int, error) {
	if bound == 0 {
		return 0, fmt.Errorf("bound cannot be equal to 0")
	}
	return 1 << (bits.Len(bound) - 1), nil
}

// ProtoToProof creates a proof from its proto representation.
func ProtoToProof(protoProof pb.Proof) Proof {
	if protoProof.Start == 0 && protoProof.End == 0 {
		return NewEmptyRangeProof(protoProof.IsMaxNamespaceIgnored)
	}

	if len(protoProof.LeafHash) > 0 {
		return NewAbsenceProof(
			int(protoProof.Start),
			int(protoProof.End),
			protoProof.Nodes,
			protoProof.LeafHash,
			protoProof.IsMaxNamespaceIgnored,
		)
	}

	return NewInclusionProof(
		int(protoProof.Start),
		int(protoProof.End),
		protoProof.Nodes,
		protoProof.IsMaxNamespaceIgnored,
	)
}

// nextSubtreeSize returns the number of leaves of the subtree adjacent to start
// that does not overlap end.
func nextSubtreeSize(start, end uint64) int {
	// the highest left subtree
	ideal := bits.TrailingZeros64(start)
	// number of bits required to represent end-start
	max := bits.Len64(end-start) - 1
	if ideal > max {
		return 1 << uint(max)
	}
	return 1 << uint(ideal)
}

// popIfNonEmpty pops the first element off of a slice only if the slice is
// non-empty, else returns a nil slice
func popIfNonEmpty(s *[][]byte) []byte {
	if len(*s) != 0 {
		first := (*s)[0]
		*s = (*s)[1:]
		return first
	}
	return nil
}

func safeIntToUint(val int) (uint, error) {
	if val < 0 {
		return 0, fmt.Errorf("cannot convert a negative int %d to uint", val)
	}
	return uint(val), nil
}
