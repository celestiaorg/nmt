package nmt

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/nmt/namespace"
)

// TestVerifyNamespace_EmptyProof tests the correct behaviour of VerifyNamespace for valid and invalid empty proofs.
func TestVerifyNamespace_EmptyProof(t *testing.T) {
	// create a tree with 4 leaves
	nIDSize := 1
	tree := exampleNMT(nIDSize, true, 1, 2, 3, 4)
	root, err := tree.Root()
	require.NoError(t, err)

	// build a proof for an NID that is outside the namespace range of the tree
	// start = end = 0, nodes = empty, leafHash = empty
	nID0 := []byte{0}
	validEmptyProof, err := tree.ProveNamespace(nID0)
	require.NoError(t, err)

	// build a proof for an NID that is within the namespace range of the tree, then corrupt it to have a zero range
	// start = end = 0, nodes = non-empty, leafHash = empty
	nID1 := []byte{1}
	invalidEmptyProof, err := tree.ProveNamespace(nID1)
	require.NoError(t, err)
	// modify the proof to contain a zero range
	invalidEmptyProof.start = 0
	invalidEmptyProof.end = 0

	// root of an empty tree
	emptyRoot := tree.treeHasher.EmptyRoot()
	hasher := tree.treeHasher.baseHasher

	type args struct {
		proof  Proof
		hasher hash.Hash
		nID    namespace.ID
		leaves [][]byte
		root   []byte
	}

	tests := []struct {
		name              string
		args              args
		want              bool
		isValidEmptyProof bool
	}{
		// in the following tests, proof should always contain an empty range

		// test cases for a non-empty tree hence non-empty root
		{"valid empty proof & empty leaves & nID not in range", args{validEmptyProof, hasher, nID0, [][]byte{}, root}, true, true},
		{"invalid empty proof & empty leaves & nID in range", args{invalidEmptyProof, hasher, nID1, [][]byte{}, root}, false, false},
		{"valid empty proof & non-empty leaves & nID not in range", args{validEmptyProof, hasher, nID0, [][]byte{{1}}, root}, false, true},
		{"valid empty proof & empty leaves & nID in range", args{validEmptyProof, hasher, nID1, [][]byte{}, root}, false, true},

		// test cases for an empty tree hence empty root
		{"valid empty proof & empty leaves & nID not in range ", args{validEmptyProof, hasher, nID0, [][]byte{}, emptyRoot}, true, true},
		{"invalid empty proof & empty leaves & nID in range", args{invalidEmptyProof, hasher, nID1, [][]byte{}, emptyRoot}, false, false},
		{"valid empty proof & non-empty leaves & nID not in range", args{validEmptyProof, hasher, nID0, [][]byte{{1}}, emptyRoot}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.True(t, tt.args.proof.IsEmptyProof() == tt.isValidEmptyProof)
			if got := tt.args.proof.VerifyNamespace(tt.args.hasher, tt.args.nID, tt.args.leaves, tt.args.root); got != tt.want {
				t.Errorf("VerifyNamespace() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProof_VerifyNamespace_False(t *testing.T) {
	const testNidLen = 3

	n := New(sha256.New(), NamespaceIDSize(testNidLen))
	data := append(append([]namespaceDataPair{
		newNamespaceDataPair([]byte{0, 0, 0}, []byte("first leaf")),
	},
		generateLeafData(testNidLen, 0, 9, []byte("data"))...,
	), newNamespaceDataPair([]byte{0, 0, 8}, []byte("last leaf")))
	for _, d := range data {
		err := n.Push(namespace.PrefixedData(append(d.ID, d.Data...)))
		if err != nil {
			t.Fatalf("invalid test setup: error on Push(): %v", err)
		}
	}

	validProof, err := n.ProveNamespace([]byte{0, 0, 0})
	if err != nil {
		t.Fatalf("invalid test setup: error on ProveNamespace(): %v", err)
	}
	// inclusion proof of the leaf index 0
	incProof0, err := n.buildRangeProof(0, 1)
	require.NoError(t, err)
	incompleteFirstNs := NewInclusionProof(0, 1, incProof0, false)
	type args struct {
		nID  namespace.ID
		data [][]byte
		root []byte
	}
	pushedZeroNs := n.Get([]byte{0, 0, 0})
	pushedLastNs := n.Get([]byte{0, 0, 8})

	// an invalid absence proof for an existing namespace ID (2) in the constructed tree
	leafIndex := 3
	inclusionProofOfLeafIndex, err := n.buildRangeProof(leafIndex, leafIndex+1)
	require.NoError(t, err)
	leafHash := n.leafHashes[leafIndex] // the only data item with namespace ID = 2 in the constructed tree is at index 3
	invalidAbsenceProof := NewAbsenceProof(leafIndex, leafIndex+1, inclusionProofOfLeafIndex, leafHash, false)

	// inclusion proof of the leaf index 10
	incProof10, err := n.buildRangeProof(10, 11)
	require.NoError(t, err)

	// root
	root, err := n.Root()
	require.NoError(t, err)

	tests := []struct {
		name  string
		proof Proof
		args  args
		want  bool
	}{
		{
			"invalid nid (too long)", validProof,
			args{[]byte{0, 0, 0, 0}, pushedZeroNs, root},
			false,
		},
		{
			"invalid leaf data (too short)", validProof,
			args{[]byte{0, 0, 0}, [][]byte{{0, 1}}, root},
			false,
		},
		{
			"mismatching IDs in data", validProof,
			args{[]byte{0, 0, 0}, append(append([][]byte(nil), pushedZeroNs...), []byte{1, 1, 1}), root},
			false,
		},
		{
			"added another leaf", validProof,
			args{[]byte{0, 0, 0}, append(append([][]byte(nil), pushedZeroNs...), []byte{0, 0, 0}), root},
			false,
		},
		{
			"remove one leaf, errors", validProof,
			args{[]byte{0, 0, 0}, pushedZeroNs[:len(pushedZeroNs)-1], root},
			false,
		},
		{
			"remove one leaf & update proof range, errors", NewInclusionProof(validProof.Start(), validProof.End()-1, validProof.Nodes(), false),
			args{[]byte{0, 0, 0}, pushedZeroNs[:len(pushedZeroNs)-1], root},
			false,
		},
		{
			"incomplete namespace proof (right)", incompleteFirstNs,
			args{[]byte{0, 0, 0}, pushedZeroNs[:len(pushedZeroNs)-1], root},
			false,
		},
		{
			"incomplete namespace proof (left)", NewInclusionProof(10, 11, incProof10, false),
			args{[]byte{0, 0, 8}, pushedLastNs[1:], root},
			false,
		},
		{
			"remove all leaves, errors", validProof,
			args{[]byte{0, 0, 0}, pushedZeroNs[:len(pushedZeroNs)-2], root},
			false,
		},
		{
			"invalid absence proof of an existing nid", invalidAbsenceProof,
			args{[]byte{0, 0, 2}, [][]byte{}, root},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// make copy of nodes for mutation check
			duplicateNodes := make([][]byte, len(tt.proof.nodes))
			for i := range tt.proof.nodes {
				duplicateNodes[i] = make([]byte, len(tt.proof.nodes[i]))
				copy(duplicateNodes[i], tt.proof.nodes[i])
			}

			got := tt.proof.VerifyNamespace(sha256.New(), tt.args.nID, tt.args.data, tt.args.root)
			if got != tt.want {
				t.Errorf("VerifyNamespace() got = %v, want %v", got, tt.want)
			}

			// check if proof was mutated during verification
			for i := range tt.proof.nodes {
				if !bytes.Equal(duplicateNodes[i], tt.proof.nodes[i]) {
					t.Errorf("VerifyNameSpace() proof got mutated during verification")
				}
			}
		})
	}
}

func TestProof_MultipleLeaves(t *testing.T) {
	n := New(sha256.New())
	ns := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	rawData := [][]byte{
		bytes.Repeat([]byte{1}, 100),
		bytes.Repeat([]byte{2}, 100),
		bytes.Repeat([]byte{3}, 100),
		bytes.Repeat([]byte{4}, 100),
		bytes.Repeat([]byte{5}, 100),
		bytes.Repeat([]byte{6}, 100),
		bytes.Repeat([]byte{7}, 100),
		bytes.Repeat([]byte{8}, 100),
	}

	for _, d := range rawData {
		err := n.Push(safeAppend(ns, d))
		if err != nil {
			t.Fatal(err)
		}
	}

	root, err := n.Root()
	require.NoError(t, err)

	type args struct {
		start, end int
		root       []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			"3rd through 5th leaf", args{2, 4, root}, true,
		},
		{
			"single leaf", args{2, 3, root}, true,
		},
		{
			"first leaf", args{0, 1, root}, true,
		},
		{
			"most leaves", args{0, 7, root}, true,
		},
		{
			"most leaves", args{0, 7, bytes.Repeat([]byte{1}, 48)}, false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof, err := n.ProveRange(tt.args.start, tt.args.end)
			if err != nil {
				t.Fatal(err)
			}
			got := proof.VerifyInclusion(sha256.New(), ns, rawData[tt.args.start:tt.args.end], tt.args.root)
			if got != tt.want {
				t.Errorf("VerifyInclusion() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func safeAppend(id, data []byte) []byte {
	return append(append(make([]byte, 0, len(id)+len(data)), id...), data...)
}

func TestVerifyLeafHashes_Err(t *testing.T) {
	// create a sample tree
	nameIDSize := 2
	nmt := exampleNMT(nameIDSize, true, 1, 2, 3, 4, 5, 6, 7, 8)
	hasher := nmt.treeHasher
	root, err := nmt.Root()
	require.NoError(t, err)

	// shrink the size of the root so that the root hash is invalid.
	corruptRoot := root[:len(root)-1]

	// create an NMT proof
	nID5 := namespace.ID{5, 5}
	proof5, err := nmt.ProveNamespace(nID5)
	require.NoError(t, err)
	// corrupt the leafHash so that the proof verification fails during the root computation.
	// note that the leaf at index 4 has the namespace ID of 5.
	leafHash5 := nmt.leafHashes[4]
	corruptLeafHash5 := leafHash5[:nmt.NamespaceSize()]

	// corrupt the leafHash: replace its namespace ID with a different one.
	nID3 := createByteSlice(nameIDSize, 3)
	leafHash5SmallerNID := concat(nID3, nID3, nmt.leafHashes[4][2*nmt.NamespaceSize():])
	require.NoError(t, hasher.ValidateNodeFormat(leafHash5SmallerNID))

	nID6 := createByteSlice(nameIDSize, 7)
	leafHash5BiggerNID := concat(nID6, nID6, nmt.leafHashes[4][2*nmt.NamespaceSize():])
	require.NoError(t, hasher.ValidateNodeFormat(leafHash5BiggerNID))

	// create nmt proof for namespace ID 4
	nID4 := namespace.ID{4, 4}
	proof4InvalidNodes, err := nmt.ProveNamespace(nID4)
	require.NoError(t, err)
	// corrupt the last node in the proof4.nodes, it resides on the right side of the proof4.end index.
	// this test scenario makes the proof verification fail when constructing the tree root from the
	// computed subtree root and the proof.nodes on the right side of the proof.end index.
	proof4InvalidNodes.nodes[2] = proof4InvalidNodes.nodes[2][:nmt.NamespaceSize()-1]
	leafHash4 := nmt.leafHashes[3]

	// create a proof with invalid range: start = end = 0
	proof4InvalidRangeSEE, err := nmt.ProveNamespace(nID4)
	require.NoError(t, err)
	proof4InvalidRangeSEE.end = 0
	proof4InvalidRangeSEE.start = 0

	// create a proof with invalid range: start > end
	proof4InvalidRangeSBE, err := nmt.ProveNamespace(nID4)
	require.NoError(t, err)
	proof4InvalidRangeSBE.start = proof4InvalidRangeSBE.end + 1

	// create a proof with invalid range: start < 0
	proof4InvalidRangeSLZ, err := nmt.ProveNamespace(nID4)
	require.NoError(t, err)
	proof4InvalidRangeSLZ.start = -1

	tests := []struct {
		name               string
		proof              Proof
		Hasher             *Hasher
		verifyCompleteness bool
		nID                namespace.ID
		leafHashes         [][]byte
		root               []byte
		wantErr            bool
	}{
		{"corrupt root", proof5, hasher, true, nID5, [][]byte{leafHash5}, corruptRoot, true},
		{"wrong leafHash: not namespaced", proof5, hasher, true, nID5, [][]byte{corruptLeafHash5}, root, true},
		{"wrong leafHash: smaller namespace", proof5, hasher, true, nID5, [][]byte{leafHash5SmallerNID}, root, true},
		{"wong leafHash: bigger namespace", proof5, hasher, true, nID5, [][]byte{leafHash5BiggerNID}, root, true},
		{"wrong proof.nodes: the last node has an incorrect format", proof4InvalidNodes, hasher, false, nID4, [][]byte{leafHash4}, root, true},
		//  the verifyCompleteness parameter in the verifyProof function should be set to false in order to bypass nodes correctness check during the completeness verification (otherwise it panics).
		{"wrong proof range: start = end", proof4InvalidRangeSEE, hasher, true, nID4, [][]byte{leafHash4}, root, true},
		{"wrong proof range: start > end", proof4InvalidRangeSBE, hasher, true, nID4, [][]byte{leafHash4}, root, true},
		{"wrong proof range: start < 0", proof4InvalidRangeSLZ, hasher, true, nID4, [][]byte{leafHash4}, root, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.proof.VerifyLeafHashes(tt.Hasher, tt.verifyCompleteness, tt.nID, tt.leafHashes, tt.root)
			assert.Equal(t, tt.wantErr, err != nil)
		})
	}
}

func TestVerifyInclusion_False(t *testing.T) {
	hasher := sha256.New()

	// create a sample tree with namespace ID size of 1
	nmt1 := exampleNMT(1, true, 1, 2, 3, 4, 5, 6, 7, 8)
	root1, err := nmt1.Root()
	require.NoError(t, err)
	nid4_1 := namespace.ID{4}
	proof4_1, err := nmt1.ProveRange(3, 4) // leaf at index 3 has namespace ID 4
	require.NoError(t, err)
	leaf4_1 := nmt1.leaves[3][nmt1.NamespaceSize():]

	// create a sample tree with namespace ID size of 2
	nmt2 := exampleNMT(2, true, 1, 2, 3, 4, 5, 6, 7, 8)
	root2, err := nmt2.Root()
	require.NoError(t, err)
	nid4_2 := namespace.ID{4, 4}
	proof4_2, err := nmt2.ProveRange(3, 4) // leaf at index 3 has namespace ID 4
	require.NoError(t, err)
	leaf4_2 := nmt2.leaves[3][nmt2.NamespaceSize():]

	require.Equal(t, leaf4_2, leaf4_1)
	leaf := leaf4_1

	type args struct {
		hasher                 hash.Hash
		nID                    namespace.ID
		leavesWithoutNamespace [][]byte
		root                   []byte
	}
	tests := []struct {
		name   string
		proof  Proof
		args   args
		result bool
	}{
		{"nID size of proof < nID size of VerifyInclusion's nmt hasher", proof4_1, args{hasher, nid4_2, [][]byte{leaf}, root2}, false},
		{"nID size of proof > nID size of VerifyInclusion's nmt hasher", proof4_2, args{hasher, nid4_1, [][]byte{leaf}, root1}, false},
		{"nID size of root < nID size of VerifyInclusion's nmt hasher", proof4_2, args{hasher, nid4_2, [][]byte{leaf}, root1}, false},
		{"nID size of root > nID size of VerifyInclusion's nmt hasher", proof4_1, args{hasher, nid4_1, [][]byte{leaf}, root2}, false},
		{"nID size of proof and root < nID size of VerifyInclusion's nmt hasher", proof4_1, args{hasher, nid4_2, [][]byte{leaf}, root1}, false},
		{"nID size of proof and root > nID size of VerifyInclusion's nmt hasher", proof4_2, args{hasher, nid4_1, [][]byte{leaf}, root2}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.proof.VerifyInclusion(tt.args.hasher, tt.args.nID, tt.args.leavesWithoutNamespace, tt.args.root)
			assert.Equal(t, tt.result, got)
		})
	}
}

// TestVerifyInclusion_EmptyProofs tests the correct behaviour of VerifyInclusion in response to valid and invalid empty proofs.
func TestVerifyInclusion_EmptyProofs(t *testing.T) {
	hasher := sha256.New()

	// create a tree
	nIDSize := 1
	tree := exampleNMT(nIDSize, true, 1, 2, 3, 4, 5, 6, 7, 8)
	root, err := tree.Root()
	require.NoError(t, err)

	sampleLeafWithoutNID := tree.leaves[3][tree.NamespaceSize():] // does not matter which leaf we choose, just a leaf that belongs to the tree
	sampleNID := tree.leaves[3][:tree.NamespaceSize()]            // the NID of the leaf we chose
	sampleNode := tree.leafHashes[7]                              // does not matter which node we choose, just a node that belongs to the tree

	// create an empty proof
	emptyProof := Proof{}
	// verify that the proof is a valid empty proof
	// this check is to ensure that we stay consistent with the definition of empty proofs
	require.True(t, emptyProof.IsEmptyProof())

	// create a non-empty proof
	nonEmptyProof := Proof{nodes: [][]byte{sampleNode}}

	type args struct {
		hasher                 hash.Hash
		nID                    namespace.ID
		leavesWithoutNamespace [][]byte
		root                   []byte
	}
	tests := []struct {
		name   string
		proof  Proof
		args   args
		result bool
	}{
		{"valid empty proof and leaves == empty", emptyProof, args{hasher, sampleNID, [][]byte{}, root}, true},
		{"valid empty proof and leaves == non-empty", emptyProof, args{hasher, sampleNID, [][]byte{sampleLeafWithoutNID}, root}, false},
		{"invalid empty proof and leaves == empty", nonEmptyProof, args{hasher, sampleNID, [][]byte{}, root}, false},
		{"invalid empty proof and leaves != empty", nonEmptyProof, args{hasher, sampleNID, [][]byte{sampleLeafWithoutNID}, root}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.proof.VerifyInclusion(tt.args.hasher, tt.args.nID, tt.args.leavesWithoutNamespace, tt.args.root)
			assert.Equal(t, tt.result, got)
		})
	}
}

func TestVerifyNamespace_False(t *testing.T) {
	nIDs := []byte{1, 2, 3, 4, 5, 6, 7, 8, 11}

	// create a sample tree with namespace ID size of 1
	nmt1 := exampleNMT(1, true, nIDs...)
	root1, err := nmt1.Root()
	require.NoError(t, err)
	nid4_1 := namespace.ID{4}
	proof4_1, err := nmt1.ProveNamespace(nid4_1) // leaf at index 3 has namespace ID 4
	require.NoError(t, err)

	// create a sample tree with namespace ID size of 2
	nmt2 := exampleNMT(2, true, nIDs...)
	root2, err := nmt2.Root()
	require.NoError(t, err)
	nid4_2 := namespace.ID{4, 4}
	proof4_2, err := nmt2.ProveNamespace(nid4_2) // leaf at index 3 has namespace ID 4
	require.NoError(t, err)

	leaf := nmt1.leaves[3]

	// create an absence proof with namespace ID size of 1
	nid9_1 := namespace.ID{9}
	absenceProof9_1, err := nmt1.ProveNamespace(nid9_1)
	require.NoError(t, err)
	require.True(t, absenceProof9_1.IsOfAbsence())

	// create an absence proof with namespace ID size of 2
	nid9_2 := namespace.ID{9, 9}
	absenceProof9_2, err := nmt2.ProveNamespace(nid9_2)
	require.NoError(t, err)
	require.True(t, absenceProof9_2.IsOfAbsence())

	// swap leafHashes of the absence proofs
	buffer := absenceProof9_2.leafHash
	absenceProof9_2.leafHash = absenceProof9_1.leafHash
	absenceProof9_1.leafHash = buffer

	hasher := sha256.New()

	type args struct {
		hasher hash.Hash
		nID    namespace.ID
		leaves [][]byte
		root   []byte
	}
	tests := []struct {
		name   string
		proof  Proof
		args   args
		result bool
	}{
		{"nID size of proof.nodes < nID size of VerifyNamespace's nmt hasher", proof4_1, args{hasher, nid4_2, [][]byte{leaf}, root2}, false},
		{"nID size of proof.nodes > nID size of VerifyNamespace's nmt hasher", proof4_2, args{hasher, nid4_1, [][]byte{leaf}, root1}, false},
		{"nID size of root < nID size of VerifyNamespace's nmt hasher", proof4_2, args{hasher, nid4_2, [][]byte{leaf}, root1}, false},
		{"nID size of root > nID size of VerifyNamespace's nmt hasher", proof4_1, args{hasher, nid4_1, [][]byte{leaf}, root2}, false},
		{"nID size of proof.leafHash < nID size of VerifyNamespace's nmt hasher", absenceProof9_2, args{hasher, nid9_2, [][]byte{}, root2}, false},
		{"nID size of proof.leafHash > nID size of VerifyNamespace's nmt hasher", absenceProof9_1, args{hasher, nid9_1, [][]byte{}, root1}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.proof.VerifyNamespace(tt.args.hasher, tt.args.nID, tt.args.leaves, tt.args.root)
			assert.Equal(t, tt.result, got)
		})
	}
}

func TestVerifyLeafHashes_False(t *testing.T) {
	nIDs := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	// create a sample tree with namespace ID size of 1
	nmt1 := exampleNMT(1, true, nIDs...)
	root1, err := nmt1.Root()
	require.NoError(t, err)
	nid4_1 := namespace.ID{4}
	proof4_1, err := nmt1.ProveNamespace(nid4_1) // leaf at index 3 has namespace ID 4
	require.NoError(t, err)

	// create a sample tree with namespace ID size of 2
	nmt2 := exampleNMT(2, true, nIDs...)
	root2, err := nmt2.Root()
	require.NoError(t, err)
	nid4_2 := namespace.ID{4, 4}
	proof4_2, err := nmt2.ProveNamespace(nid4_2) // leaf at index 3 has namespace ID 4
	require.NoError(t, err)

	leafHash1 := nmt1.leafHashes[3]
	leafHash2 := nmt2.leafHashes[3]

	type args struct {
		nIDSize namespace.IDSize
		nID     namespace.ID
		leaves  [][]byte
		root    []byte
	}
	tests := []struct {
		name   string
		proof  Proof
		args   args
		result bool
	}{
		{"nID size of proof < nID size of VerifyLeafHashes' nmt hasher", proof4_1, args{2, nid4_2, [][]byte{leafHash2}, root2}, false},
		{"nID size of proof > nID size of VerifyLeafHashes' nmt hasher", proof4_2, args{1, nid4_1, [][]byte{leafHash1}, root1}, false},
		{"nID size of root < nID size of VerifyLeafHashes' nmt hasher", proof4_2, args{2, nid4_2, [][]byte{leafHash2}, root1}, false},
		{"nID size of root > nID size of VerifyLeafHashes' nmt hasher", proof4_1, args{1, nid4_1, [][]byte{leafHash1}, root2}, false},
		{"size of queried nID > nID size of VerifyLeafHashes' nmt hasher", proof4_1, args{1, nid4_2, [][]byte{leafHash1}, root1}, false},
		{"size of queried nID < nID size of VerifyLeafHashes' nmt hasher", proof4_2, args{2, nid4_1, [][]byte{leafHash2}, root2}, false},
		{"nID size of leafHash < nID size of VerifyLeafHashes' nmt hasher", proof4_2, args{2, nid4_2, [][]byte{leafHash1}, root2}, false},
		{"nID size of leafHash > nID size of VerifyLeafHashes' nmt hasher", proof4_1, args{1, nid4_1, [][]byte{leafHash2}, root1}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := NewNmtHasher(sha256.New(), tt.args.nIDSize, true)
			got, _ := tt.proof.VerifyLeafHashes(hasher, true, tt.args.nID, tt.args.leaves, tt.args.root)
			assert.Equal(t, tt.result, got)
		})
	}
}

func TestIsEmptyProof(t *testing.T) {
	tests := []struct {
		name     string
		proof    Proof
		expected bool
	}{
		{
			name: "valid empty proof",
			proof: Proof{
				leafHash: nil,
				nodes:    nil,
				start:    1,
				end:      1,
			},
			expected: true,
		},
		{
			name: "invalid empty proof - start != end",
			proof: Proof{
				leafHash: nil,
				nodes:    nil,
				start:    0,
				end:      1,
			},
			expected: false,
		},
		{
			name: "invalid empty proof - non-empty nodes",
			proof: Proof{
				leafHash: nil,
				nodes:    [][]byte{{0x01}},
				start:    1,
				end:      1,
			},
			expected: false,
		},
		{
			name: "invalid absence proof - non-empty leafHash",
			proof: Proof{
				leafHash: []byte{0x01},
				nodes:    nil,
				start:    1,
				end:      1,
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.proof.IsEmptyProof()
			assert.Equal(t, test.expected, result)
		})
	}
}

// TestIsEmptyProofOverlapAbsenceProof ensures there is no overlap between empty proofs and absence proofs.
func TestIsEmptyProofOverlapAbsenceProof(t *testing.T) {
	tests := []struct {
		name  string
		proof Proof
	}{
		{
			name: "valid empty proof",
			proof: Proof{
				leafHash: nil,
				nodes:    nil,
				start:    1,
				end:      1,
			},
		},
		{
			name: "valid absence proof",
			proof: Proof{
				leafHash: []byte{0x01, 0x02, 0x03},
				nodes:    nil,
				start:    1,
				end:      1,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.proof.IsEmptyProof()
			absenceResult := test.proof.IsOfAbsence()
			if result {
				assert.False(t, absenceResult)
			}
			if absenceResult {
				assert.False(t, result)
			}
		})
	}
}
