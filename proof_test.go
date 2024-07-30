package nmt

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/nmt/namespace"
	pb "github.com/celestiaorg/nmt/pb"
)

func TestJsonMarshal_Proof(t *testing.T) {
	// create a tree with 4 leaves
	nIDSize := 1
	tree := exampleNMT(nIDSize, true, 1, 2, 3, 4)

	// build a proof for an NID that is within the namespace range of the tree
	nID := []byte{1}
	proof, err := tree.ProveNamespace(nID)
	require.NoError(t, err)

	// marshal the proof to JSON
	jsonProof, err := proof.MarshalJSON()
	require.NoError(t, err)

	// unmarshal the proof from JSON
	var unmarshalledProof Proof
	err = unmarshalledProof.UnmarshalJSON(jsonProof)
	require.NoError(t, err)

	// verify that the unmarshalled proof is equal to the original proof
	assert.Equal(t, proof, unmarshalledProof)
}

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
	hasher := sha256.New()
	emptyRoot := tree.treeHasher.EmptyRoot()

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
	nmthasher := nmt.treeHasher
	hasher := nmthasher.(*NmtHasher)
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
		Hasher             *NmtHasher
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

func TestVerifyInclusion_MismatchingRange(t *testing.T) {
	nIDs := []byte{1, 2, 3, 4, 6, 6, 6, 9}
	nmt := exampleNMT(1, true, nIDs...)
	root, err := nmt.Root()
	require.NoError(t, err)

	nid6 := namespace.ID{6}
	// node at index 5 has namespace ID 6
	incProof6, err := nmt.ProveNamespace(nid6)
	require.NoError(t, err)
	// leaves with namespace ID 6
	leaf4 := nmt.leaves[4][nmt.NamespaceSize():]
	leaf5 := nmt.leaves[5][nmt.NamespaceSize():]
	leaf6 := nmt.leaves[6][nmt.NamespaceSize():]

	type args struct {
		nIDSize                namespace.IDSize
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
		{
			"inclusion proof: size of proof's range = size of leavesWithoutNamespace",
			incProof6,
			args{1, nid6, [][]byte{leaf4, leaf5, leaf6}, root},
			true,
		},
		{
			"inclusion proof: size of proof's range > size of" +
				" a non-empty leavesWithoutNamespace",
			incProof6,
			args{1, nid6, [][]byte{leaf4, leaf5}, root},
			false,
		},
		{
			"inclusion proof: size of proof's range > size of" +
				" an empty leavesWithoutNamespace",
			incProof6,
			args{1, nid6, [][]byte{}, root},
			false,
		},
		{
			"inclusion proof: size of proof's range < size of" +
				" leavesWithoutNamespace",
			incProof6,
			args{1, nid6, [][]byte{leaf4, leaf5, leaf6, leaf6}, root},
			false,
		},
		{
			// in this testcase the nameID does not really matter since the
			// leaves are empty
			"empty proof: size of proof's range = size of leavesWithoutNamespace",
			Proof{start: 1, end: 1},
			args{1, nid6, [][]byte{}, root},
			true,
		},
		{
			"empty proof: size of proof's range < size of" +
				" leavesWithoutNamespace",
			Proof{start: 1, end: 1},
			args{1, nid6, [][]byte{leaf4, leaf5, leaf6}, root},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := sha256.New()
			got := tt.proof.VerifyInclusion(hasher, tt.args.nID,
				tt.args.leavesWithoutNamespace, tt.args.root)
			assert.Equal(t, tt.result, got)
		})
	}
}

func TestVerifyLeafHashes_MismatchingRange(t *testing.T) {
	nIDs := []byte{1, 2, 3, 4, 6, 6, 6, 9}
	nmt := exampleNMT(1, true, nIDs...)
	root, err := nmt.Root()
	require.NoError(t, err)

	nid5 := namespace.ID{5}
	// namespace 5 does not exist in the tree, hence the proof is an absence proof
	absenceProof5, err := nmt.ProveNamespace(nid5)
	require.NoError(t, err)
	leafHash5 := nmt.leafHashes[4]

	nid6 := namespace.ID{6}
	// node at index 5 has namespace ID 6
	incProof6, err := nmt.Prove(5)
	require.NoError(t, err)
	leafHash6 := nmt.leafHashes[5]

	type args struct {
		nIDSize    namespace.IDSize
		nID        namespace.ID
		leafHashes [][]byte
		root       []byte
	}
	tests := []struct {
		name   string
		proof  Proof
		args   args
		result bool
		err    error
	}{
		{
			"absence proof: size of proof's range = size of leafHashes",
			absenceProof5,
			args{1, namespace.ID{5}, [][]byte{leafHash5}, root},
			true, nil,
		},
		{
			"absence proof: size of proof's range > size of leafHashes",
			absenceProof5,
			args{1, nid5, [][]byte{}, root},
			false, ErrWrongLeafHashesSize,
		},
		{
			"absence proof: size of proof's range < size of leafHashes",
			absenceProof5,
			args{1, nid5, [][]byte{leafHash5, leafHash5}, root},
			false, ErrWrongLeafHashesSize,
		},
		{
			"inclusion proof: size of proof's range = size of leafHashes",
			incProof6,
			args{1, nid6, [][]byte{leafHash6}, root},
			true, nil,
		},
		{
			"inclusion proof: size of proof's range > size of leafHashes",
			incProof6,
			args{1, nid6, [][]byte{}, root},
			false, ErrWrongLeafHashesSize,
		},
		{
			"inclusion proof: size of proof's range < size of leafHashes",
			incProof6,
			args{1, nid6, [][]byte{leafHash6, leafHash6}, root},
			false,
			ErrWrongLeafHashesSize,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := NewNmtHasher(sha256.New(), tt.args.nIDSize, true)
			got, err := tt.proof.VerifyLeafHashes(hasher, false, tt.args.nID,
				tt.args.leafHashes, tt.args.root)
			assert.Equal(t, tt.result, got)
			if tt.err != nil {
				assert.ErrorAs(t, err, &tt.err)
			}
		})
	}
}

func TestVerifyLeafHashes_False(t *testing.T) {
	nIDs := []byte{1, 2, 3, 4, 6, 7, 8, 9}

	// create a sample tree with namespace ID size of 1
	nmt1 := exampleNMT(1, true, nIDs...)
	root1, err := nmt1.Root()
	require.NoError(t, err)
	nid4_1 := namespace.ID{4}
	proof4_1, err := nmt1.ProveNamespace(nid4_1) // leaf at index 3 has namespace ID 4
	require.NoError(t, err)

	leafHash1 := nmt1.leafHashes[3]

	// corrupt the namespace of the leafHash
	leafHash1Corrupted := make([]byte, len(leafHash1))
	copy(leafHash1Corrupted, leafHash1)
	leafHash1Corrupted[0] = 0 // change the min namespace
	leafHash1Corrupted[1] = 0 // change the max namespace

	// create an absence proof with namespace ID size of 1
	nid5_1 := namespace.ID{5}
	absenceProof5_1, err := nmt1.ProveNamespace(nid5_1)
	require.NoError(t, err)
	leafHash6_1 := nmt1.leafHashes[4]
	assert.Equal(t, leafHash6_1, absenceProof5_1.leafHash)

	// create a sample tree with namespace ID size of 2
	nmt2 := exampleNMT(2, true, nIDs...)
	root2, err := nmt2.Root()
	require.NoError(t, err)
	nid4_2 := namespace.ID{4, 4}
	proof4_2, err := nmt2.ProveNamespace(nid4_2) // leaf at index 3 has namespace ID 4
	require.NoError(t, err)

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
		{
			"nID size of proof < nID size of VerifyLeafHashes' nmt hasher",
			proof4_1,
			args{2, nid4_2, [][]byte{leafHash2}, root2},
			false,
		},
		{"nID size of proof > nID size of VerifyLeafHashes' nmt hasher", proof4_2, args{1, nid4_1, [][]byte{leafHash1}, root1}, false},
		{"nID size of root < nID size of VerifyLeafHashes' nmt hasher", proof4_2, args{2, nid4_2, [][]byte{leafHash2}, root1}, false},
		{"nID size of root > nID size of VerifyLeafHashes' nmt hasher", proof4_1, args{1, nid4_1, [][]byte{leafHash1}, root2}, false},
		{"size of queried nID > nID size of VerifyLeafHashes' nmt hasher", proof4_1, args{1, nid4_2, [][]byte{leafHash1}, root1}, false},
		{"size of queried nID < nID size of VerifyLeafHashes' nmt hasher", proof4_2, args{2, nid4_1, [][]byte{leafHash2}, root2}, false},
		{"nID size of leafHash < nID size of VerifyLeafHashes' nmt hasher", proof4_2, args{2, nid4_2, [][]byte{leafHash1}, root2}, false},
		{"nID size of leafHash > nID size of VerifyLeafHashes' nmt hasher", proof4_1, args{1, nid4_1, [][]byte{leafHash2}, root1}, false},
		{"nID of leafHashes do not match the queried nID", proof4_1, args{1, nid4_1, [][]byte{leafHash1Corrupted}, root1}, false},
		{"absence proof: nID of leafHashes do not match the queried nID, which is a valid case", absenceProof5_1, args{1, nid5_1, [][]byte{leafHash6_1}, root1}, true},
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

// TestVerifyNamespace_ShortAbsenceProof_Valid checks whether VerifyNamespace
// can correctly verify short namespace absence proofs
func TestVerifyNamespace_ShortAbsenceProof_Valid(t *testing.T) {
	// create a Merkle tree with 8 leaves
	tree := exampleNMT(1, true, 1, 2, 3, 4, 6, 7, 8, 9)
	qNS := []byte{5} // does not belong to the tree
	root, err := tree.Root()
	assert.NoError(t, err)
	// In the following illustration, nodes are suffixed with the range
	// of leaves they cover, with the upper bound being non-inclusive.
	// For example, Node3_4 denotes a node that covers the 3rd leaf (excluding the 4th leaf),
	// while Node4_6 represents the node that covers the 4th and 5th leaves.
	//
	//                                        Node0_8                                  Tree Root
	//                            /                            \
	//                        /                                 \
	//                  Node0_4                             Node4_8                    Non-Leaf Node
	//               /            \                     /                \
	//             /                \                 /                    \
	//       Node0_2             Node2_4         Node4_6              Node6_8          Non-Leaf Node
	//      /      \            /     \           /    \               /     \
	// Node0_1   Node1_2   Node2_3  Node3_4   Node4_5  Node5_6  Node6_7   Node7_8      Leaf Hash
	//     1         2          3        4       6       7           8        9        Leaf namespace
	//     0         1          2        3       4       5           6        7        Leaf index

	// nodes needed for the full absence proof of qNS
	Node4_5 := tree.leafHashes[4]
	Node5_6 := tree.leafHashes[5]
	Node6_8, err := tree.computeRoot(6, 8)
	assert.NoError(t, err)
	Node0_4, err := tree.computeRoot(0, 4)
	assert.NoError(t, err)

	// nodes needed for the short absence proof of qNS; the proof of inclusion
	// of the parent of Node4_5

	Node4_6, err := tree.computeRoot(4, 6)
	assert.NoError(t, err)

	// nodes needed for another short absence parent of qNS; the proof of
	// inclusion of the grandparent of Node4_5
	Node4_8, err := tree.computeRoot(4, 8)
	assert.NoError(t, err)

	tests := []struct {
		name     string
		qNID     []byte
		leafHash []byte
		nodes    [][]byte
		start    int
		end      int
	}{
		{
			name:     "valid full absence proof",
			qNID:     qNS,
			leafHash: Node4_5,
			nodes:    [][]byte{Node0_4, Node5_6, Node6_8},
			start:    4, // the index position of leafHash at its respective level
			end:      5,
		},
		{
			name:     "valid short absence proof: one level higher",
			qNID:     qNS,
			leafHash: Node4_6,
			nodes:    [][]byte{Node0_4, Node6_8},
			start:    2, // the index position of leafHash at its respective level
			end:      3,
		},
		{
			name:     "valid short absence proof: two levels higher",
			qNID:     qNS,
			leafHash: Node4_8,
			nodes:    [][]byte{Node0_4},
			start:    1, // the index position of leafHash at its respective level
			end:      2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof := Proof{
				leafHash: tt.leafHash,
				nodes:    tt.nodes,
				start:    tt.start,
				end:      tt.end,
			}

			res := proof.VerifyNamespace(sha256.New(), qNS, nil, root)
			assert.True(t, res)
		})
	}
}

// TestVerifyNamespace_ShortAbsenceProof_Invalid checks whether VerifyNamespace rejects invalid short absence proofs.
func TestVerifyNamespace_ShortAbsenceProof_Invalid(t *testing.T) {
	// create a Merkle tree with 8 leaves
	tree := exampleNMT(1, true, 1, 2, 3, 4, 6, 8, 8, 8)
	qNS := []byte{7} // does not belong to the tree
	root, err := tree.Root()
	assert.NoError(t, err)
	// In the following illustration, nodes are suffixed with the range
	// of leaves they cover, with the upper bound being non-inclusive.
	// For example, Node3_4 denotes a node that covers the 3rd leaf (excluding the 4th leaf),
	// while Node4_6 represents the node that covers the 4th and 5th leaves.
	//
	//                                       Node0_8                                  Tree Root
	//                            /                            \
	//                        /                                 \
	//                  Node0_4                              Node4_8                   Non-Leaf Node
	//               /            \                     /                \
	//             /                \                 /                    \
	//      Node0_2            Node2_4           Node4_6                Node6_8        Non-Leaf Node
	//      /      \            /     \           /    \               /     \
	// Node0_1   Node1_2    Node2_3  Node3_4  Node4_5  Node5_6     Node6_7 Node7_8     Leaf Hash
	//     1         2          3        4       6       8           8        8        Leaf namespace
	//     0         1          2        3       4       5           6        7        Leaf index

	// nodes needed for the full absence proof of qNS
	Node5_6 := tree.leafHashes[5]
	Node4_5 := tree.leafHashes[4]
	Node6_8, err := tree.computeRoot(6, 8)
	assert.NoError(t, err)
	Node0_4, err := tree.computeRoot(0, 4)
	assert.NoError(t, err)

	// nodes needed for the short absence proof of qNS; the proof of inclusion of the parent of Node5_6;
	// the verification should fail since the namespace range o Node4_6, the parent, has overlap with the qNS i.e., 7
	Node4_6, err := tree.computeRoot(4, 6)
	assert.NoError(t, err)

	// nodes needed for another short absence parent of qNS; the proof of inclusion of the grandparent of Node5_6
	// the verification should fail since the namespace range of Node4_8, the grandparent, has overlap with the qNS i.e., 7
	Node4_8, err := tree.computeRoot(4, 8)
	assert.NoError(t, err)

	tests := []struct {
		name     string
		qNID     []byte
		leafHash []byte
		nodes    [][]byte
		start    int
		end      int
		want     bool
	}{
		{
			name:     "valid full absence proof",
			qNID:     qNS,
			leafHash: Node5_6,
			nodes:    [][]byte{Node0_4, Node4_5, Node6_8},
			start:    5, // the index position of leafHash at its respective level
			end:      6,
			want:     true,
		},
		{
			name:     "invalid short absence proof: one level higher",
			qNID:     qNS,
			leafHash: Node4_6,
			nodes:    [][]byte{Node0_4, Node6_8},
			start:    2, // the index position of leafHash at its respective level
			end:      3,
			want:     false,
		},
		{
			name:     "invalid short absence proof: two levels higher",
			qNID:     qNS,
			leafHash: Node4_8,
			nodes:    [][]byte{Node0_4},
			start:    1, // the index position of leafHash at its respective level
			end:      2,
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof := Proof{
				leafHash: tt.leafHash,
				nodes:    tt.nodes,
				start:    tt.start,
				end:      tt.end,
			}

			res := proof.VerifyNamespace(sha256.New(), qNS, nil, root)
			assert.Equal(t, tt.want, res)
		})
	}
}

func Test_ProtoToProof(t *testing.T) {
	verifier := func(t *testing.T, proof Proof, protoProof pb.Proof) {
		require.Equal(t, int64(proof.Start()), protoProof.Start)
		require.Equal(t, int64(proof.End()), protoProof.End)
		require.Equal(t, proof.Nodes(), protoProof.Nodes)
		require.Equal(t, proof.LeafHash(), protoProof.LeafHash)
		require.Equal(t, proof.IsMaxNamespaceIDIgnored(), protoProof.IsMaxNamespaceIgnored)
	}

	tests := []struct {
		name       string
		protoProof pb.Proof
		verifyFn   func(t *testing.T, proof Proof, protoProof pb.Proof)
	}{
		{
			name: "Inclusion proof",
			protoProof: pb.Proof{
				Start:                 0,
				End:                   1,
				Nodes:                 [][]byte{bytes.Repeat([]byte{1}, 10)},
				LeafHash:              nil,
				IsMaxNamespaceIgnored: true,
			},
			verifyFn: verifier,
		},
		{
			name: "Absence Proof",
			protoProof: pb.Proof{
				Start:                 0,
				End:                   1,
				Nodes:                 [][]byte{bytes.Repeat([]byte{1}, 10)},
				LeafHash:              bytes.Repeat([]byte{1}, 10),
				IsMaxNamespaceIgnored: true,
			},
			verifyFn: verifier,
		},
		{
			name: "Empty Proof",
			protoProof: pb.Proof{
				Start:                 0,
				End:                   0,
				Nodes:                 [][]byte{bytes.Repeat([]byte{1}, 10)},
				LeafHash:              nil,
				IsMaxNamespaceIgnored: true,
			},
			verifyFn: func(t *testing.T, proof Proof, protoProof pb.Proof) {
				require.Equal(t, proof.Start(), 0)
				require.Equal(t, proof.End(), 0)
				require.Nil(t, proof.Nodes())
				require.Nil(t, proof.LeafHash())
				require.Equal(t, proof.IsMaxNamespaceIDIgnored(), protoProof.IsMaxNamespaceIgnored)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof := ProtoToProof(tt.protoProof)
			tt.verifyFn(t, proof, tt.protoProof)
		})
	}
}

func TestLargestPowerOfTwo(t *testing.T) {
	tests := []struct {
		bound       uint
		expected    int
		expectError bool
	}{
		{bound: 1, expected: 1},
		{bound: 2, expected: 2},
		{bound: 3, expected: 2},
		{bound: 4, expected: 4},
		{bound: 5, expected: 4},
		{bound: 6, expected: 4},
		{bound: 7, expected: 4},
		{bound: 8, expected: 8},
		{bound: 0, expectError: true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("bound=%d", tt.bound), func(t *testing.T) {
			result, err := largestPowerOfTwo(tt.bound)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestToLeafRanges(t *testing.T) {
	tests := []struct {
		proofStart, proofEnd, subtreeWidth int
		expectedRanges                     []LeafRange
		expectError                        bool
	}{
		{
			proofStart:   0,
			proofEnd:     8,
			subtreeWidth: 1,
			expectedRanges: []LeafRange{
				{Start: 0, End: 1},
				{Start: 1, End: 2},
				{Start: 2, End: 3},
				{Start: 3, End: 4},
				{Start: 4, End: 5},
				{Start: 5, End: 6},
				{Start: 6, End: 7},
				{Start: 7, End: 8},
			},
		},
		{
			proofStart:   0,
			proofEnd:     9,
			subtreeWidth: 1,
			expectedRanges: []LeafRange{
				{Start: 0, End: 1},
				{Start: 1, End: 2},
				{Start: 2, End: 3},
				{Start: 3, End: 4},
				{Start: 4, End: 5},
				{Start: 5, End: 6},
				{Start: 6, End: 7},
				{Start: 7, End: 8},
				{Start: 8, End: 9},
			},
		},
		{
			proofStart:   0,
			proofEnd:     16,
			subtreeWidth: 1,
			expectedRanges: []LeafRange{
				{Start: 0, End: 1},
				{Start: 1, End: 2},
				{Start: 2, End: 3},
				{Start: 3, End: 4},
				{Start: 4, End: 5},
				{Start: 5, End: 6},
				{Start: 6, End: 7},
				{Start: 7, End: 8},
				{Start: 8, End: 9},
				{Start: 9, End: 10},
				{Start: 10, End: 11},
				{Start: 11, End: 12},
				{Start: 12, End: 13},
				{Start: 13, End: 14},
				{Start: 14, End: 15},
				{Start: 15, End: 16},
			},
		},
		{
			proofStart:   0,
			proofEnd:     100,
			subtreeWidth: 2,
			expectedRanges: func() []LeafRange {
				var ranges []LeafRange
				for i := 0; i < 100; i = i + 2 {
					ranges = append(ranges, LeafRange{i, i + 2})
				}
				return ranges
			}(),
		},
		{
			proofStart:   0,
			proofEnd:     150,
			subtreeWidth: 4,
			expectedRanges: func() []LeafRange {
				var ranges []LeafRange
				for i := 0; i < 148; i = i + 4 {
					ranges = append(ranges, LeafRange{i, i + 4})
				}
				ranges = append(ranges, LeafRange{
					Start: 148,
					End:   150,
				})
				return ranges
			}(),
		},
		{
			proofStart:   0,
			proofEnd:     400,
			subtreeWidth: 8,
			expectedRanges: func() []LeafRange {
				var ranges []LeafRange
				for i := 0; i < 400; i = i + 8 {
					ranges = append(ranges, LeafRange{i, i + 8})
				}
				return ranges
			}(),
		},
		{
			proofStart:     -1,
			proofEnd:       0,
			subtreeWidth:   -1,
			expectedRanges: nil,
			expectError:    true,
		},
		{
			proofStart:     0,
			proofEnd:       -1,
			subtreeWidth:   -1,
			expectedRanges: nil,
			expectError:    true,
		},
		{
			proofStart:     0,
			proofEnd:       0,
			subtreeWidth:   2,
			expectedRanges: nil,
			expectError:    true,
		},
		{
			proofStart:     0,
			proofEnd:       0,
			subtreeWidth:   -1,
			expectedRanges: nil,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("proofStart=%d, proofEnd=%d, subtreeWidth=%d", tt.proofStart, tt.proofEnd, tt.subtreeWidth), func(t *testing.T) {
			result, err := ToLeafRanges(tt.proofStart, tt.proofEnd, tt.subtreeWidth)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.True(t, compareRanges(result, tt.expectedRanges))
			}
		})
	}
}

func compareRanges(a, b []LeafRange) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestNextLeafRange(t *testing.T) {
	tests := []struct {
		currentStart, currentEnd int
		// the maximum leaf range == subtree width used in these tests do not follow ADR-013
		// they're just used to try different test cases
		subtreeRootMaximumLeafRange int
		expectedRange               LeafRange
		expectError                 bool
	}{
		{
			currentStart:                0,
			currentEnd:                  8,
			subtreeRootMaximumLeafRange: 4,
			expectedRange:               LeafRange{Start: 0, End: 4},
		},
		{
			currentStart:                4,
			currentEnd:                  10,
			subtreeRootMaximumLeafRange: 8,
			expectedRange:               LeafRange{Start: 4, End: 8},
		},
		{
			currentStart:                4,
			currentEnd:                  20,
			subtreeRootMaximumLeafRange: 2,
			expectedRange:               LeafRange{Start: 4, End: 6},
		},
		{
			currentStart:                4,
			currentEnd:                  20,
			subtreeRootMaximumLeafRange: 4,
			expectedRange:               LeafRange{Start: 4, End: 8},
		},
		{
			currentStart:                0,
			currentEnd:                  1,
			subtreeRootMaximumLeafRange: 1,
			expectedRange:               LeafRange{Start: 0, End: 1},
		},
		{
			currentStart:                0,
			currentEnd:                  16,
			subtreeRootMaximumLeafRange: 16,
			expectedRange:               LeafRange{Start: 0, End: 16},
		},
		{
			currentStart:                0,
			currentEnd:                  0,
			subtreeRootMaximumLeafRange: 4,
			expectError:                 true,
		},
		{
			currentStart:                5,
			currentEnd:                  2,
			subtreeRootMaximumLeafRange: 4,
			expectError:                 true,
		},
		{
			currentStart:                5,
			currentEnd:                  2,
			subtreeRootMaximumLeafRange: 0,
			expectError:                 true,
		},
		{ // A range not referencing any inner node
			currentStart:                1,
			currentEnd:                  3,
			subtreeRootMaximumLeafRange: 4,
			expectError:                 true,
		},
		{ // A range not referencing any inner node
			currentStart:                1,
			currentEnd:                  5,
			subtreeRootMaximumLeafRange: 4,
			expectError:                 true,
		},
		{ // A range not referencing any inner node
			currentStart:                1,
			currentEnd:                  6,
			subtreeRootMaximumLeafRange: 4,
			expectError:                 true,
		},
		{ // A range not referencing any inner node
			currentStart:                1,
			currentEnd:                  7,
			subtreeRootMaximumLeafRange: 4,
			expectError:                 true,
		},
		{ // A range not referencing any inner node
			currentStart:                2,
			currentEnd:                  8,
			subtreeRootMaximumLeafRange: 4,
			expectError:                 true,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("currentStart=%d, currentEnd=%d, subtreeRootMaximumLeafRange=%d", tt.currentStart, tt.currentEnd, tt.subtreeRootMaximumLeafRange), func(t *testing.T) {
			result, err := nextLeafRange(tt.currentStart, tt.currentEnd, tt.subtreeRootMaximumLeafRange)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedRange, result)
			}
		})
	}
}

func TestSafeIntToUint(t *testing.T) {
	tests := []struct {
		input         int
		expectedUint  uint
		expectedError error
	}{
		{
			input:         10,
			expectedUint:  10,
			expectedError: nil,
		},
		{
			input:         0,
			expectedUint:  0,
			expectedError: nil,
		},
		{
			input:         -5,
			expectedUint:  0,
			expectedError: fmt.Errorf("cannot convert a negative int %d to uint", -5),
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("input=%d", tt.input), func(t *testing.T) {
			result, err := safeIntToUint(tt.input)
			if (err != nil) != (tt.expectedError != nil) || (err != nil && err.Error() != tt.expectedError.Error()) {
				t.Errorf("expected error %v, got %v", tt.expectedError, err)
			}
			if result != tt.expectedUint {
				t.Errorf("expected uint %v, got %v", tt.expectedUint, result)
			}
		})
	}
}

func TestMinInt(t *testing.T) {
	tests := []struct {
		val1, val2 int
		expected   int
	}{
		{
			val1:     10,
			val2:     20,
			expected: 10,
		},
		{
			val1:     -5,
			val2:     6,
			expected: -5,
		},
		{
			val1:     5,
			val2:     -6,
			expected: -6,
		},
		{
			val1:     -5,
			val2:     -6,
			expected: -6,
		},
		{
			val1:     0,
			val2:     0,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("val1=%d, val2=%d", tt.val1, tt.val2), func(t *testing.T) {
			result := minInt(tt.val1, tt.val2)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestVerifySubtreeRootInclusion(t *testing.T) {
	tree := exampleNMT(1, true, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
	root, err := tree.Root()
	require.NoError(t, err)

	nmthasher := tree.treeHasher
	hasher := nmthasher.(*NmtHasher)

	tests := []struct {
		proof        Proof
		subtreeRoots [][]byte
		// the subtree widths used in these tests do not follow ADR-013
		// they're just used to try different test cases
		subtreeWidth int
		root         []byte
		validProof   bool
		expectError  bool
	}{
		{
			proof: func() Proof {
				p, err := tree.ProveRange(0, 8)
				require.NoError(t, err)
				return p
			}(),
			subtreeRoots: func() [][]byte {
				subtreeRoot, err := tree.ComputeSubtreeRoot(0, 8)
				require.NoError(t, err)
				return [][]byte{subtreeRoot}
			}(),
			subtreeWidth: 8,
			root:         root,
			validProof:   true,
		},
		{
			proof: func() Proof {
				p, err := tree.ProveRange(0, 1)
				require.NoError(t, err)
				return p
			}(),
			subtreeRoots: func() [][]byte {
				subtreeRoot, err := tree.ComputeSubtreeRoot(0, 1)
				require.NoError(t, err)
				return [][]byte{subtreeRoot}
			}(),
			subtreeWidth: 8,
			root:         root,
			validProof:   true,
		},
		{
			proof: func() Proof {
				p, err := tree.ProveRange(0, 2)
				require.NoError(t, err)
				return p
			}(),
			subtreeRoots: func() [][]byte {
				subtreeRoot, err := tree.ComputeSubtreeRoot(0, 2)
				require.NoError(t, err)
				return [][]byte{subtreeRoot}
			}(),
			subtreeWidth: 8,
			root:         root,
			validProof:   true,
		},
		{
			proof: func() Proof {
				p, err := tree.ProveRange(2, 4)
				require.NoError(t, err)
				return p
			}(),
			subtreeRoots: func() [][]byte {
				subtreeRoot, err := tree.ComputeSubtreeRoot(2, 4)
				require.NoError(t, err)
				return [][]byte{subtreeRoot}
			}(),
			subtreeWidth: 8,
			root:         root,
			validProof:   true,
		},
		{
			proof: func() Proof {
				p, err := tree.ProveRange(0, 8)
				require.NoError(t, err)
				return p
			}(),
			subtreeRoots: func() [][]byte {
				subtreeRoot1, err := tree.ComputeSubtreeRoot(0, 4)
				require.NoError(t, err)
				subtreeRoot2, err := tree.ComputeSubtreeRoot(4, 8)
				require.NoError(t, err)
				return [][]byte{subtreeRoot1, subtreeRoot2}
			}(),
			subtreeWidth: 4,
			root:         root,
			validProof:   true,
		},
		{
			proof: func() Proof {
				p, err := tree.ProveRange(0, 8)
				require.NoError(t, err)
				return p
			}(),
			subtreeRoots: func() [][]byte {
				subtreeRoot1, err := tree.ComputeSubtreeRoot(0, 2)
				require.NoError(t, err)
				subtreeRoot2, err := tree.ComputeSubtreeRoot(2, 4)
				require.NoError(t, err)
				subtreeRoot3, err := tree.ComputeSubtreeRoot(4, 6)
				require.NoError(t, err)
				subtreeRoot4, err := tree.ComputeSubtreeRoot(6, 8)
				require.NoError(t, err)
				return [][]byte{subtreeRoot1, subtreeRoot2, subtreeRoot3, subtreeRoot4}
			}(),
			subtreeWidth: 2,
			root:         root,
			validProof:   true,
		},
		{
			proof: func() Proof {
				p, err := tree.ProveRange(0, 8)
				require.NoError(t, err)
				return p
			}(),
			subtreeRoots: func() [][]byte {
				subtreeRoot1, err := tree.ComputeSubtreeRoot(0, 1)
				require.NoError(t, err)
				subtreeRoot2, err := tree.ComputeSubtreeRoot(1, 2)
				require.NoError(t, err)
				subtreeRoot3, err := tree.ComputeSubtreeRoot(2, 3)
				require.NoError(t, err)
				subtreeRoot4, err := tree.ComputeSubtreeRoot(3, 4)
				require.NoError(t, err)
				subtreeRoot5, err := tree.ComputeSubtreeRoot(4, 5)
				require.NoError(t, err)
				subtreeRoot6, err := tree.ComputeSubtreeRoot(5, 6)
				require.NoError(t, err)
				subtreeRoot7, err := tree.ComputeSubtreeRoot(6, 7)
				require.NoError(t, err)
				subtreeRoot8, err := tree.ComputeSubtreeRoot(7, 8)
				require.NoError(t, err)
				return [][]byte{subtreeRoot1, subtreeRoot2, subtreeRoot3, subtreeRoot4, subtreeRoot5, subtreeRoot6, subtreeRoot7, subtreeRoot8}
			}(),
			subtreeWidth: 1,
			root:         root,
			validProof:   true,
		},
		{
			proof: func() Proof {
				p, err := tree.ProveRange(4, 8)
				require.NoError(t, err)
				return p
			}(),
			subtreeRoots: func() [][]byte {
				subtreeRoot, err := tree.ComputeSubtreeRoot(4, 8)
				require.NoError(t, err)
				return [][]byte{subtreeRoot}
			}(),
			subtreeWidth: 8,
			root:         root,
			validProof:   true,
		},
		{
			proof: func() Proof {
				p, err := tree.ProveRange(12, 14)
				require.NoError(t, err)
				return p
			}(),
			subtreeRoots: func() [][]byte {
				subtreeRoot, err := tree.ComputeSubtreeRoot(12, 14)
				require.NoError(t, err)
				return [][]byte{subtreeRoot}
			}(),
			subtreeWidth: 8,
			root:         root,
			validProof:   true,
		},
		{
			proof: func() Proof {
				p, err := tree.ProveRange(14, 16)
				require.NoError(t, err)
				return p
			}(),
			subtreeRoots: func() [][]byte {
				subtreeRoot, err := tree.ComputeSubtreeRoot(14, 16)
				require.NoError(t, err)
				return [][]byte{subtreeRoot}
			}(),
			subtreeWidth: 8,
			root:         root,
			validProof:   true,
		},
		{
			proof: func() Proof {
				p, err := tree.ProveRange(14, 15)
				require.NoError(t, err)
				return p
			}(),
			subtreeRoots: func() [][]byte {
				subtreeRoot, err := tree.ComputeSubtreeRoot(14, 15)
				require.NoError(t, err)
				return [][]byte{subtreeRoot}
			}(),
			subtreeWidth: 8,
			root:         root,
			validProof:   true,
		},
		{
			proof: func() Proof {
				p, err := tree.ProveRange(15, 16)
				require.NoError(t, err)
				return p
			}(),
			subtreeRoots: func() [][]byte {
				subtreeRoot, err := tree.ComputeSubtreeRoot(15, 16)
				require.NoError(t, err)
				return [][]byte{subtreeRoot}
			}(),
			subtreeWidth: 8,
			root:         root,
			validProof:   true,
		},
		{
			proof: func() Proof {
				p, err := tree.ProveRange(15, 16)
				require.NoError(t, err)
				return p
			}(),
			subtreeRoots: func() [][]byte {
				subtreeRoot, err := tree.ComputeSubtreeRoot(15, 16)
				require.NoError(t, err)
				return [][]byte{subtreeRoot}
			}(),
			subtreeWidth: -3, // invalid subtree root width
			root:         root,
			expectError:  true,
		},
		{
			proof: func() Proof {
				p, err := tree.ProveRange(15, 16)
				require.NoError(t, err)
				return p
			}(),
			subtreeRoots: func() [][]byte {
				subtreeRoot, err := tree.ComputeSubtreeRoot(15, 16)
				require.NoError(t, err)
				return [][]byte{subtreeRoot, subtreeRoot} // invalid number of subtree roots
			}(),
			subtreeWidth: 8,
			root:         root,
			expectError:  true,
		},
		{
			proof: func() Proof {
				p, err := tree.ProveRange(15, 16)
				require.NoError(t, err)
				return p
			}(),
			subtreeRoots: func() [][]byte {
				subtreeRoot, err := tree.ComputeSubtreeRoot(15, 16)
				require.NoError(t, err)
				return [][]byte{subtreeRoot}
			}(),
			subtreeWidth: 8,
			root:         []byte("random root"), // invalid root format
			expectError:  true,
		},
		{
			proof: Proof{start: -1}, // invalid start
			subtreeRoots: func() [][]byte {
				subtreeRoot, err := tree.ComputeSubtreeRoot(15, 16)
				require.NoError(t, err)
				return [][]byte{subtreeRoot}
			}(),
			subtreeWidth: 8,
			root:         root,
			expectError:  true,
		},
		{
			proof: Proof{end: 1, start: 2}, // invalid end
			subtreeRoots: func() [][]byte {
				subtreeRoot, err := tree.ComputeSubtreeRoot(15, 16)
				require.NoError(t, err)
				return [][]byte{subtreeRoot}
			}(),
			subtreeWidth: 8,
			root:         root,
			expectError:  true,
		},
		{
			proof: Proof{
				start: 0,
				end:   4,
				nodes: [][]byte{[]byte("invalid proof node")}, // invalid proof node
			},
			subtreeRoots: func() [][]byte {
				subtreeRoot, err := tree.ComputeSubtreeRoot(15, 16)
				require.NoError(t, err)
				return [][]byte{subtreeRoot}
			}(),
			subtreeWidth: 8,
			root:         root,
			expectError:  true,
		},
		{
			proof: func() Proof {
				p, err := tree.ProveRange(15, 16)
				require.NoError(t, err)
				return p
			}(),
			subtreeRoots: [][]byte{[]byte("invalid subtree root")}, // invalid subtree root
			subtreeWidth: 8,
			root:         root,
			expectError:  true,
		},
		{
			proof: func() Proof {
				p, err := tree.ProveRange(0, 8)
				require.NoError(t, err)
				return p
			}(),
			subtreeRoots: func() [][]byte {
				subtreeRoot1, err := tree.ComputeSubtreeRoot(0, 4)
				require.NoError(t, err)
				return [][]byte{subtreeRoot1} // will error because it requires the subtree root of [4,8) too
			}(),
			subtreeWidth: 4,
			root:         root,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("proofStart=%d, proofEnd=%d, subTreeWidth=%d", tt.proof.Start(), tt.proof.End(), tt.subtreeWidth), func(t *testing.T) {
			result, err := tt.proof.VerifySubtreeRootInclusion(hasher, tt.subtreeRoots, tt.subtreeWidth, tt.root)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.validProof, result)
			}
		})
	}
}

// TestVerifySubtreeRootInclusion_infiniteRecursion is motivated by a failing test
// case in celestia-node
func TestVerifySubtreeRootInclusion_infiniteRecursion(t *testing.T) {
	namespaceIDs := bytes.Repeat([]byte{1}, 64)
	tree := exampleNMT(1, true, namespaceIDs...)
	root, err := tree.Root()
	require.NoError(t, err)

	nmthasher := tree.treeHasher
	hasher := nmthasher.(*NmtHasher)
	subtreeRoot, err := tree.ComputeSubtreeRoot(0, 4)
	require.NoError(t, err)
	subtreeRoots := [][]byte{subtreeRoot, subtreeRoot, subtreeRoot, subtreeRoot, subtreeRoot, subtreeRoot, subtreeRoot}
	subtreeWidth := 8

	proof, err := tree.ProveRange(19, 64)
	require.NoError(t, err)

	require.NotPanics(t, func() {
		// This previously hits:
		// runtime: goroutine stack exceeds 1000000000-byte limit
		// runtime: sp=0x14020160480 stack=[0x14020160000, 0x14040160000]
		// fatal error: stack overflow
		_, err = proof.VerifySubtreeRootInclusion(hasher, subtreeRoots, subtreeWidth, root)
		require.Error(t, err)
	})
}
