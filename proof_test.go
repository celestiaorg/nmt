package nmt

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/celestiaorg/merkletree"
	"github.com/celestiaorg/nmt/namespace"
)

type TreeHasher interface {
	merkletree.TreeHasher
	Size() int
}

// CachedSubtreeHasher implements SubtreeHasher using a set of precomputed
// leaf hashes.
type cachedSubtreeHasher struct {
	leafHashes [][]byte
	TreeHasher
}

// NextSubtreeRoot implements SubtreeHasher.
func (csh *cachedSubtreeHasher) NextSubtreeRoot(subtreeSize int) ([]byte, error) {
	if len(csh.leafHashes) == 0 {
		return nil, io.EOF
	}
	tree := merkletree.NewFromTreehasher(csh.TreeHasher)
	for i := 0; i < subtreeSize && len(csh.leafHashes) > 0; i++ {
		if err := tree.PushSubTree(0, csh.leafHashes[0]); err != nil {
			return nil, err
		}
		csh.leafHashes = csh.leafHashes[1:]
	}
	return tree.Root(), nil
}

// Skip implements SubtreeHasher.
func (csh *cachedSubtreeHasher) Skip(n int) error {
	if n > len(csh.leafHashes) {
		return io.ErrUnexpectedEOF
	}
	csh.leafHashes = csh.leafHashes[n:]
	return nil
}

// NewCachedSubtreeHasher creates a CachedSubtreeHasher using the specified
// leaf hashes and hash function.
func NewCachedSubtreeHasher(leafHashes [][]byte, h TreeHasher) *cachedSubtreeHasher {
	return &cachedSubtreeHasher{
		leafHashes: leafHashes,
		TreeHasher: h,
	}
}

func TestProof_VerifyNamespace_False(t *testing.T) {
	const testNidLen = 3

	n := New(sha256.New(), NamespaceIDSize(testNidLen))
	data := append(append([]namespaceDataPair{
		newNamespaceDataPair([]byte{0, 0, 0}, []byte("first leaf"))},
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
	incompleteFirstNs := NewInclusionProof(0, 1, rangeProof(t, n, 0, 1), false)
	type args struct {
		nID  namespace.ID
		data [][]byte
		root []byte
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

func rangeProof(t *testing.T, n *NamespacedMerkleTree, start, end int) [][]byte {
	n.computeLeafHashesIfNecessary()
	subTreeHasher := NewCachedSubtreeHasher(n.leafHashes, n.treeHasher)
	incompleteRange, err := merkletree.BuildRangeProof(start, end, subTreeHasher)
	if err != nil {
		t.Fatalf("Could not create range proof: %v", err)
	}
	return incompleteRange
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
			"3rd through 5th leaf", args{2, 4, n.Root()}, true,
		},
		{
			"single leaf", args{2, 3, n.Root()}, true,
		},
		{
			"first leaf", args{0, 1, n.Root()}, true,
		},
		{
			"most leaves", args{0, 7, n.Root()}, true,
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
