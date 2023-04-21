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
	tree := exampleNMT(nIDSize, 1, 2, 3, 4)
	root, err := tree.Root()
	require.NoError(t, err)

	// build a proof for an NID that is outside tree range of the tree
	nID0 := []byte{0}
	validEmptyProof, err := tree.ProveNamespace(nID0)
	require.NoError(t, err)
	data0 := [][]byte{}

	// build a proof for an NID that is within the namespace range of the tree
	nID1 := []byte{1}
	invalidEmptyProof, err := tree.ProveNamespace([]byte{1})
	require.NoError(t, err)
	data1 := [][]byte{tree.leaves[0]}
	// modify the proof to be empty
	invalidEmptyProof.start = invalidEmptyProof.end

	hasher := sha256.New()
	type args struct {
		proof  Proof
		hasher hash.Hash
		nID    namespace.ID
		leaves [][]byte
		root   []byte
	}

	tests := []struct {
		name string
		args args
		want bool
	}{
		{"valid empty proof", args{validEmptyProof, hasher, nID0, data0, root}, true},
		{"invalid empty proof", args{invalidEmptyProof, hasher, nID1, data1, root}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	nmt := exampleNMT(2, 1, 2, 3, 4, 5, 6, 7, 8)
	hasher := nmt.treeHasher
	root, err := nmt.Root()
	require.NoError(t, err)

	// create an NMT proof
	nID5 := namespace.ID{5, 5}
	proof5, err := nmt.ProveNamespace(nID5)
	require.NoError(t, err)
	// corrupt the leafHash so that the proof verification fails during the root computation.
	// note that the leaf at index 4 has the namespace ID of 5.
	leafHash5 := nmt.leafHashes[4][:nmt.NamespaceSize()]

	// create nmt proof for namespace ID 4
	nID4 := namespace.ID{4, 4}
	proof4, err := nmt.ProveNamespace(nID4)
	require.NoError(t, err)
	// corrupt the last node in the proof4.nodes, it resides on the right side of the proof4.end index.
	// this test scenario makes the proof verification fail when constructing the tree root from the
	// computed subtree root and the proof.nodes on the right side of the proof.end index.
	proof4.nodes[2] = proof4.nodes[2][:nmt.NamespaceSize()-1]
	leafHash4 := nmt.leafHashes[3]

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
		{"wrong leafHash: not namespaced", proof5, hasher, true, nID5, [][]byte{leafHash5}, root, true},
		{"wrong leafHash: incorrect namespace", proof5, hasher, true, nID5, [][]byte{{10, 10, 10, 10}}, root, true},
		{"wrong proof.nodes: the last node has an incorrect format", proof4, hasher, false, nID4, [][]byte{leafHash4}, root, true},
		//  the verifyCompleteness parameter in the verifyProof function should be set to false in order to bypass nodes correctness check during the completeness verification (otherwise it panics).
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.proof.verifyLeafHashes(tt.Hasher, tt.verifyCompleteness, tt.nID, tt.leafHashes, tt.root)
			assert.Equal(t, tt.wantErr, err != nil)
		})
	}
}

func TestVerifyInclusion_False(t *testing.T) {
	hasher := sha256.New()

	// create a sample tree with namespace ID size of 1
	nmt1 := exampleNMT(1, 1, 2, 3, 4, 5, 6, 7, 8)
	root1, err := nmt1.Root()
	require.NoError(t, err)
	nid4_1 := namespace.ID{4}
	proof4_1, err := nmt1.ProveRange(3, 4) // leaf at index 3 has namespace ID 4
	require.NoError(t, err)
	leaf4_1 := nmt1.leaves[3][nmt1.NamespaceSize():]

	// create a sample tree with namespace ID size of 2
	nmt2 := exampleNMT(2, 1, 2, 3, 4, 5, 6, 7, 8)
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

func TestVerifyNamespace_False(t *testing.T) {
	nIDs := []byte{1, 2, 3, 4, 5, 6, 7, 8, 11}

	// create a sample tree with namespace ID size of 1
	nmt1 := exampleNMT(1, nIDs...)
	root1, err := nmt1.Root()
	require.NoError(t, err)
	nid4_1 := namespace.ID{4}
	proof4_1, err := nmt1.ProveNamespace(nid4_1) // leaf at index 3 has namespace ID 4
	require.NoError(t, err)

	// create a sample tree with namespace ID size of 2
	nmt2 := exampleNMT(2, nIDs...)
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
		{"nID size of proof < nID size of VerifyNamespace's nmt hasher", proof4_1, args{hasher, nid4_2, [][]byte{leaf}, root2}, false},
		{"nID size of proof > nID size of VerifyNamespace's nmt hasher", proof4_2, args{hasher, nid4_1, [][]byte{leaf}, root1}, false},
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
	nmt1 := exampleNMT(1, nIDs...)
	root1, err := nmt1.Root()
	require.NoError(t, err)
	nid4_1 := namespace.ID{4}
	proof4_1, err := nmt1.ProveNamespace(nid4_1) // leaf at index 3 has namespace ID 4
	require.NoError(t, err)

	// create a sample tree with namespace ID size of 2
	nmt2 := exampleNMT(2, nIDs...)
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
		{"nID size of proof < nID size of verifyLeafHashes' nmt hasher", proof4_1, args{2, nid4_2, [][]byte{leafHash2}, root2}, false},
		{"nID size of proof > nID size of verifyLeafHashes' nmt hasher", proof4_2, args{1, nid4_1, [][]byte{leafHash1}, root1}, false},
		{"nID size of root < nID size of verifyLeafHashes' nmt hasher", proof4_2, args{2, nid4_2, [][]byte{leafHash2}, root1}, false},
		{"nID size of root > nID size of verifyLeafHashes' nmt hasher", proof4_1, args{1, nid4_1, [][]byte{leafHash1}, root2}, false},
		{"size of queried nID > nID size of verifyLeafHashes' nmt hasher", proof4_1, args{1, nid4_2, [][]byte{leafHash1}, root1}, false},
		{"size of queried nID < nID size of verifyLeafHashes' nmt hasher", proof4_2, args{2, nid4_1, [][]byte{leafHash2}, root2}, false},
		{"nID size of leafHash < nID size of verifyLeafHashes' nmt hasher", proof4_2, args{2, nid4_2, [][]byte{leafHash1}, root2}, false},
		{"nID size of leafHash > nID size of verifyLeafHashes' nmt hasher", proof4_1, args{1, nid4_1, [][]byte{leafHash2}, root1}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := NewNmtHasher(sha256.New(), tt.args.nIDSize, true)
			got, _ := tt.proof.verifyLeafHashes(hasher, true, tt.args.nID, tt.args.leaves, tt.args.root)
			assert.Equal(t, tt.result, got)
		})
	}
}
