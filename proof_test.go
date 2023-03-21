package nmt

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/nmt/namespace"
)

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
	require.NoError(t, n.computeLeafHashesIfNecessary())
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

func Test_verifyLeafHashes_Err(t *testing.T) {
	// create a sample tree
	nmt := exampleTreeWithEightLeaves()
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
		{" wrong leafHash: not namespaced", proof5, hasher, true, nID5, [][]byte{leafHash5}, root, true},
		{" wrong leafHash: incorrect namespace", proof5, hasher, true, nID5, [][]byte{{10, 10, 10, 10}}, root, true},
		{" wrong proof.nodes: the last node has an incorrect format", proof4, hasher, false, nID4, [][]byte{leafHash4}, root, true},
		//  the verifyCompleteness parameter in the verifyProof function should be set to false in order to bypass nodes correctness check during the completeness verification (otherwise it panics).
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.proof.verifyLeafHashes(tt.Hasher, tt.verifyCompleteness, tt.nID, tt.leafHashes, tt.root)
			assert.Equal(t, tt.wantErr, err != nil)
		})
	}
}
