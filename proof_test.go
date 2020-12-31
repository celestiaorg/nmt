package nmt

import (
	"crypto/sha256"
	"testing"

	"github.com/lazyledger/merkletree"

	"github.com/lazyledger/nmt/internal"
	"github.com/lazyledger/nmt/namespace"
)

func TestProof_VerifyNamespace_False(t *testing.T) {
	const testNidLen = 3

	n := New(sha256.New(), NamespaceIDSize(testNidLen))
	data := append(append([]namespace.PrefixedData{
		namespace.PrefixedDataFrom([]byte{0, 0, 0}, []byte("first leaf"))},
		generateLeafData(testNidLen, 0, 9, []byte("data"))...,
	), namespace.PrefixedDataFrom([]byte{0, 0, 8}, []byte("last leaf")))
	for _, d := range data {
		err := n.Push(d.NamespaceID(), d.Data())
		if err != nil {
			t.Fatalf("invalid test setup: error on Push(): %v", err)
		}
	}

	validProof, err := n.ProveNamespace([]byte{0, 0, 0})
	if err != nil {
		t.Fatalf("invalid test setup: error on ProveNamespace(): %v", err)
	}
	incompleteFirstNs := NewInclusionProof(0, 1, rangeProof(t, n, 0, 1), false)
	type args struct {
		nID  namespace.ID
		data [][]byte
		root namespace.IntervalDigest
	}
	pushedZeroNs := n.Get([]byte{0, 0, 0})
	pushedLastNs := n.Get([]byte{0, 0, 8})
	tests := []struct {
		name  string
		proof Proof
		args  args
		want  bool
	}{
		{"invalid nid (too long)", validProof,
			args{[]byte{0, 0, 0, 0}, pushedZeroNs, n.Root()},
			false},
		{"invalid leaf data (too short)", validProof,
			args{[]byte{0, 0, 0}, [][]byte{{0, 1}}, n.Root()},
			false},
		{"mismatching IDs in data", validProof,
			args{[]byte{0, 0, 0}, append(append([][]byte(nil), pushedZeroNs...), []byte{1, 1, 1}), n.Root()},
			false},
		{"added another leaf", validProof,
			args{[]byte{0, 0, 0}, append(append([][]byte(nil), pushedZeroNs...), []byte{0, 0, 0}), n.Root()},
			false},
		{"remove one leaf, errors", validProof,
			args{[]byte{0, 0, 0}, pushedZeroNs[:len(pushedZeroNs)-1], n.Root()},
			false},
		{"remove one leaf & update proof range, errors", NewInclusionProof(validProof.Start(), validProof.End()-1, validProof.Nodes(), false),
			args{[]byte{0, 0, 0}, pushedZeroNs[:len(pushedZeroNs)-1], n.Root()},
			false},
		{"incomplete namespace proof (right)", incompleteFirstNs,
			args{[]byte{0, 0, 0}, pushedZeroNs[:len(pushedZeroNs)-1], n.Root()},
			false},
		{"incomplete namespace proof (left)", NewInclusionProof(10, 11, rangeProof(t, n, 10, 11), false),
			args{[]byte{0, 0, 8}, pushedLastNs[1:], n.Root()},
			false},
		{"remove all leaves, errors", validProof,
			args{[]byte{0, 0, 0}, pushedZeroNs[:len(pushedZeroNs)-2], n.Root()},
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.proof.VerifyNamespace(sha256.New(), tt.args.nID, tt.args.data, tt.args.root)
			if got != tt.want {
				t.Errorf("VerifyNamespace() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func rangeProof(t *testing.T, n *NamespacedMerkleTree, start, end int) [][]byte {
	n.computeLeafHashesIfNecessary()
	subTreeHasher := internal.NewCachedSubtreeHasher(n.leafHashes, n.treeHasher)
	incompleteRange, err := merkletree.BuildRangeProof(start, end, subTreeHasher)
	if err != nil {
		t.Fatalf("Could not create range proof: %v", err)
	}
	return incompleteRange
}
