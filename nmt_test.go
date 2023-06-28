package nmt

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/nmt/namespace"
	"github.com/stretchr/testify/assert"
)

// prefixedData8 like namespace.PrefixedData is just a slice of bytes. It
// assumes that the slice it represents is at least 8 bytes. This assumption is
// not enforced by the type system though.
type prefixedData8 []byte

func (d prefixedData8) NamespaceID() namespace.ID {
	return namespace.ID(d[:8])
}

func (d prefixedData8) Data() []byte {
	return d[8:]
}

type namespaceDataPair struct {
	ID   namespace.ID
	Data []byte
}

func newNamespaceDataPair(id namespace.ID, data []byte) namespaceDataPair {
	return namespaceDataPair{
		ID:   id,
		Data: data,
	}
}

func newNamespaceDataPairRaw(nidSize int, data []byte) namespaceDataPair {
	return namespaceDataPair{
		ID:   data[:nidSize],
		Data: data[nidSize:],
	}
}

func TestExampleNamespacedMerkleTree(t *testing.T) {
	data := [][]byte{
		append(namespace.ID{0}, []byte("leaf_0")...),
		append(namespace.ID{0}, []byte("leaf_1")...),
		append(namespace.ID{1}, []byte("leaf_2")...),
		append(namespace.ID{1}, []byte("leaf_3")...),
	}
	nidSize := 1
	tree := New(sha256.New(), NamespaceIDSize(nidSize))

	for _, d := range data {
		err := tree.Push(d)
		assert.NoError(t, err)
	}

	root, err := tree.Root()
	assert.NoError(t, err)

	// the root's min/max namespace is the min and max namespace of all leaves:
	minNS := MinNamespace(root, tree.NamespaceSize())
	maxNS := MaxNamespace(root, tree.NamespaceSize())
	assert.Equal(t, minNS, []byte(namespace.ID{0}))
	assert.Equal(t, maxNS, []byte(namespace.ID{1}))

	// compute proof for namespace 0
	proof, err := tree.ProveNamespace(namespace.ID{0})
	assert.NoError(t, err)

	// verify proof using the root and the leaves of namespace 0
	leafs := [][]byte{
		append(namespace.ID{0}, []byte("leaf_0")...),
		append(namespace.ID{0}, []byte("leaf_1")...),
	}

	got := proof.VerifyNamespace(sha256.New(), namespace.ID{0}, leafs, root)
	assert.True(t, got)

	got = proof.VerifyNamespace(sha256.New(), namespace.ID{2}, leafs, root)
	assert.False(t, got) // namespace 2 is not in the tree, so the proof should fail to verify
}

func TestNamespacedMerkleTree_Push(t *testing.T) {
	tests := []struct {
		name    string
		data    namespace.PrefixedData
		wantErr bool
	}{
		{"1st push: always OK", append([]byte{0, 0, 0}, []byte("dummy data")...), false},
		{"push with same namespace: OK", append([]byte{0, 0, 0}, []byte("dummy data")...), false},
		{"push with greater namespace: OK", append([]byte{0, 0, 1}, []byte("dummy data")...), false},
		{"push with smaller namespace: Err", append([]byte{0, 0, 0}, []byte("dummy data")...), true},
		{"push with same namespace: Ok", append([]byte{0, 0, 1}, []byte("dummy data")...), false},
		{"push with greater namespace: Ok", append([]byte{1, 0, 0}, []byte("dummy data")...), false},
		{"push with smaller namespace: Err", append([]byte{0, 0, 1}, []byte("dummy data")...), true},
		{"push with smaller namespace: Err", append([]byte{0, 0, 0}, []byte("dummy data")...), true},
		{"push with smaller namespace: Err", append([]byte{0, 1, 0}, []byte("dummy data")...), true},
		{"push with same as last namespace: OK", append([]byte{1, 0, 0}, []byte("dummy data")...), false},
		{"push with greater as last namespace: OK", append([]byte{1, 1, 0}, []byte("dummy data")...), false},
		// This will error, as the NMT will treat the first bytes as the namespace. If the passed data is
		// too short though, it can't extract the namespace and hence will complain:
		{"push with wrong namespace size: Err", []byte{1, 1}, true},
	}
	n := New(sha256.New(), NamespaceIDSize(3))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := n.Push(tt.data); (err != nil) != tt.wantErr {
				t.Errorf("Push() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNamespacedMerkleTreeRoot(t *testing.T) {
	// does some sanity checks on root computation
	zeroNs := []byte{0, 0, 0}
	onesNS := []byte{1, 1, 1}
	leafData := []byte("leaf1")
	zeroLeafHash := sum(crypto.SHA256, []byte{LeafPrefix}, zeroNs, leafData)
	oneLeafHash := sum(crypto.SHA256, []byte{LeafPrefix}, onesNS, leafData)
	zeroFlaggedLeaf := append(append(zeroNs, zeroNs...), zeroLeafHash...)
	oneFlaggedLeaf := append(append(onesNS, onesNS...), oneLeafHash...)
	twoZeroLeafsRoot := sum(crypto.SHA256, []byte{NodePrefix}, zeroFlaggedLeaf, zeroFlaggedLeaf)
	diffNSLeafsRoot := sum(crypto.SHA256, []byte{NodePrefix}, zeroFlaggedLeaf, oneFlaggedLeaf)
	emptyRoot := crypto.SHA256.New().Sum(nil)

	tests := []struct {
		name       string
		nidLen     int
		pushedData []namespaceDataPair
		wantRoot   []byte
	}{
		// default empty root according to base case:
		// https://github.com/celestiaorg/celestiaorg-specs/blob/master/specs/data_structures.md#namespace-merkle-tree
		{"Empty", 3, nil, appendAll(zeroNs, zeroNs, emptyRoot)},
		{"One leaf", 3, []namespaceDataPair{newNamespaceDataPair(zeroNs, leafData)}, appendAll(zeroNs, zeroNs, sum(crypto.SHA256, []byte{LeafPrefix}, zeroNs, leafData))},
		{"Two leaves", 3, []namespaceDataPair{newNamespaceDataPair(zeroNs, leafData), newNamespaceDataPair(zeroNs, leafData)}, appendAll(zeroNs, zeroNs, twoZeroLeafsRoot)},
		{"Two leaves diff namespaces", 3, []namespaceDataPair{newNamespaceDataPair(zeroNs, leafData), newNamespaceDataPair(onesNS, leafData)}, appendAll(zeroNs, onesNS, diffNSLeafsRoot)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := New(sha256.New(), NamespaceIDSize(tt.nidLen))
			for _, d := range tt.pushedData {
				if err := n.Push(namespace.PrefixedData(append(d.ID, d.Data...))); err != nil {
					t.Errorf("Push() error = %v, expected no error", err)
				}
			}
			gotRoot, err := n.Root()
			require.NoError(t, err)
			if !reflect.DeepEqual(gotRoot, tt.wantRoot) {
				t.Errorf("Root() gotRoot = %v, want %v", gotRoot, tt.wantRoot)
			}
		})
	}
}

func appendAll(slices ...[]byte) []byte {
	totalLen := 0
	for _, slice := range slices {
		totalLen += len(slice)
	}
	out := make([]byte, 0, totalLen)
	for _, slice := range slices {
		out = append(out, slice...)
	}
	return out
}

func TestNamespacedMerkleTree_ProveNamespace_Ranges_And_Verify(t *testing.T) {
	tests := []struct {
		name           string
		nidLen         int
		pushData       []namespaceDataPair
		proveNID       namespace.ID
		wantProofStart int
		wantProofEnd   int
		wantFound      bool
	}{
		{
			"found", 1,
			generateLeafData(1, 0, 1, []byte("_data")),
			[]byte{0},
			0, 1,
			true,
		},
		{
			"not found", 1,
			generateLeafData(1, 0, 1, []byte("_data")),
			[]byte{1},
			0, 0,
			false,
		},
		{
			"two leaves and found", 1,
			append(generateLeafData(1, 0, 1, []byte("_data")), generateLeafData(1, 1, 2, []byte("_data"))...),
			[]byte{1},
			1, 2,
			true,
		},
		{
			"two leaves and found2", 1,
			repeat(generateLeafData(1, 0, 1, []byte("_data")), 2),
			[]byte{1},
			0, 0, false,
		},
		{
			"three leaves and found", 1,
			append(repeat(generateLeafData(1, 0, 1, []byte("_data")), 2), generateLeafData(1, 1, 2, []byte("_data"))...),
			[]byte{1},
			2, 3,
			true,
		},
		{
			"three leaves and not found but with range", 2,
			append(repeat(generateLeafData(2, 0, 1, []byte("_data")), 2), newNamespaceDataPair([]byte{1, 1}, []byte("_data"))),
			[]byte{0, 1},
			2, 3,
			false,
		},
		{
			"5 leaves and not found but within range", 2,
			append(generateLeafData(2, 0, 4, []byte("_data")), newNamespaceDataPair([]byte{1, 1}, []byte("_data"))),
			[]byte{1, 0},
			4, 5,
			false,
		},
		// In the cases (nID < minNID) or (maxNID < nID) we do not generate any proof
		// and the (minNS, maxNs, root) should be indication enough that nID is not in that range.
		{
			"4 leaves, not found and nID < minNID", 2,
			[]namespaceDataPair{newNamespaceDataPairRaw(2, []byte("01_data")), newNamespaceDataPairRaw(2, []byte("01_data")), newNamespaceDataPairRaw(2, []byte("01_data")), newNamespaceDataPairRaw(2, []byte("11_data"))},
			[]byte("00"),
			0, 0,
			false,
		},
		{
			"4 leaves, not found and nID > maxNID ", 2,
			[]namespaceDataPair{newNamespaceDataPairRaw(2, []byte("00_data")), newNamespaceDataPairRaw(2, []byte("00_data")), newNamespaceDataPairRaw(2, []byte("01_data")), newNamespaceDataPairRaw(2, []byte("01_data"))},
			[]byte("11"),
			0, 0,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := New(sha256.New(), NamespaceIDSize(tt.nidLen))
			for _, d := range tt.pushData {
				err := n.Push(namespace.PrefixedData(append(d.ID, d.Data...)))
				if err != nil {
					t.Fatalf("invalid test case: %v, error on Push(): %v", tt.name, err)
				}
			}
			gotProof, err := n.ProveNamespace(tt.proveNID)
			if err != nil {
				t.Fatalf("ProveNamespace() unexpected error: %v", err)
			}
			if gotProof.Start() != tt.wantProofStart {
				t.Errorf("ProveNamespace() gotProofStart = %v, want %v", gotProof.Start(), tt.wantProofStart)
			}
			if gotProof.End() != tt.wantProofEnd {
				t.Errorf("ProveNamespace() gotProofEnd = %v, want %v", gotProof.End(), tt.wantProofEnd)
			}
			gotFound := gotProof.IsNonEmptyRange() && len(gotProof.LeafHash()) == 0
			if gotFound != tt.wantFound {
				t.Errorf("Proof.ProveNamespace() gotFound = %v, wantFound = %v ", gotFound, tt.wantFound)
			}
			if gotFound && len(tt.pushData) > 1 && len(gotProof.Nodes()) == 0 {
				t.Errorf("Proof.Nodes() returned empty array, want: len(gotProof.Nodes()) > 0, gotProof: %v", gotProof)
			}

			// Verification round-trip should always pass:
			gotGetLeaves := n.Get(tt.proveNID)
			r, err := n.Root()
			require.NoError(t, err)
			gotChecksOut := gotProof.VerifyNamespace(sha256.New(), tt.proveNID, gotGetLeaves, r)
			if !gotChecksOut {
				t.Errorf("Proof.VerifyNamespace() gotChecksOut: %v, want: true", gotChecksOut)
			}

			// VerifyInclusion for each pushed leaf should always pass:
			if !gotProof.IsOfAbsence() && tt.wantFound {
				for idx, data := range tt.pushData {
					gotSingleProof, err := n.Prove(idx)
					if err != nil {
						t.Fatalf("unexpected error on Prove(): %v", err)
					}
					r, err := n.Root()
					require.NoError(t, err)
					gotChecksOut := gotSingleProof.VerifyInclusion(sha256.New(), data.ID, [][]byte{data.Data}, r)
					if !gotChecksOut {
						t.Errorf("Proof.VerifyInclusion() gotChecksOut: %v, want: true", gotChecksOut)
					}
				}
			}

			// GetWithProof equiv. to Get and ProveNamespace
			gotGetWithProoftLeaves, gotGetProof, err := n.GetWithProof(tt.proveNID)
			if err != nil {
				t.Fatalf("GetWithProof() unexpected error: %v", err)
			}
			if !reflect.DeepEqual(gotGetProof, gotProof) {
				t.Fatalf("GetWithProof() got Proof %v, want: %v", gotGetProof, gotProof)
			}

			if !reflect.DeepEqual(gotGetWithProoftLeaves, gotGetLeaves) {
				t.Fatalf("GetWithProof() got data: %v, want: %v", gotGetLeaves, tt.pushData)
			}
		})
	}
}

func TestIgnoreMaxNamespace(t *testing.T) {
	var (
		hash      = sha256.New()
		nidSize   = 8
		minNID    = []byte{0, 0, 0, 0, 0, 0, 0, 0}
		secondNID = []byte{0, 0, 0, 0, 0, 0, 0, 1}
		thirdNID  = []byte{0, 0, 0, 0, 0, 0, 0, 2}
		maxNID    = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	)

	tests := []struct {
		name               string
		ignoreMaxNamespace bool
		pushData           []prefixedData8
		wantRootMaxNID     namespace.ID
	}{
		{
			"single leaf with MaxNID (ignored)",
			true,
			[]prefixedData8{prefixedData8(append(maxNID, []byte("leaf_1")...))},
			maxNID,
		},
		{
			"single leaf with MaxNID (not ignored)",
			false,
			[]prefixedData8{prefixedData8(append(maxNID, []byte("leaf_1")...))},
			maxNID,
		},
		{
			"two leaves, one with MaxNID (ignored)",
			true,
			[]prefixedData8{
				prefixedData8(append(secondNID, []byte("leaf_1")...)),
				prefixedData8(append(maxNID, []byte("leaf_2")...)),
			},
			secondNID,
		},
		{
			"two leaves, one with MaxNID (not ignored)",
			false,
			[]prefixedData8{
				prefixedData8(append(secondNID, []byte("leaf_1")...)),
				prefixedData8(append(maxNID, []byte("leaf_2")...)),
			},
			maxNID,
		},
		{
			"two leaves with MaxNID (ignored)",
			true,
			[]prefixedData8{
				prefixedData8(append(maxNID, []byte("leaf_1")...)),
				prefixedData8(append(maxNID, []byte("leaf_2")...)),
			},
			maxNID,
		},
		{
			"two leaves with MaxNID (not ignored)",
			false,
			[]prefixedData8{
				prefixedData8(append(maxNID, []byte("leaf_1")...)),
				prefixedData8(append(maxNID, []byte("leaf_2")...)),
			},
			maxNID,
		},
		{
			"two leaves, none with MaxNID (ignored)",
			true,
			[]prefixedData8{
				prefixedData8(append(minNID, []byte("leaf_1")...)),
				prefixedData8(append(secondNID, []byte("leaf_2")...)),
			},
			secondNID,
		},
		{
			"two leaves, none with MaxNID (not ignored)",
			false,
			[]prefixedData8{
				prefixedData8(append(minNID, []byte("leaf_1")...)),
				prefixedData8(append(secondNID, []byte("leaf_2")...)),
			},
			secondNID,
		},
		{
			"three leaves, one with MaxNID (ignored)",
			true,
			[]prefixedData8{
				prefixedData8(append(minNID, []byte("leaf_1")...)),
				prefixedData8(append(secondNID, []byte("leaf_2")...)),
				prefixedData8(append(maxNID, []byte("leaf_2")...)),
			},
			secondNID,
		},
		{
			"three leaves, one with MaxNID (not ignored)",
			false,
			[]prefixedData8{
				prefixedData8(append(minNID, []byte("leaf_1")...)),
				prefixedData8(append(secondNID, []byte("leaf_2")...)),
				prefixedData8(append(maxNID, []byte("leaf_2")...)),
			},
			maxNID,
		},

		{
			"4 leaves, none maxNID (ignored)", true,
			[]prefixedData8{
				prefixedData8(append(minNID, []byte("leaf_1")...)),
				prefixedData8(append(minNID, []byte("leaf_2")...)),
				prefixedData8(append(secondNID, []byte("leaf_3")...)),
				prefixedData8(append(thirdNID, []byte("leaf_4")...)),
			},
			thirdNID,
		},
		{
			"4 leaves, half maxNID (ignored)",
			true,
			[]prefixedData8{
				prefixedData8(append(minNID, []byte("leaf_1")...)),
				prefixedData8(append(secondNID, []byte("leaf_2")...)),
				prefixedData8(append(maxNID, []byte("leaf_3")...)),
				prefixedData8(append(maxNID, []byte("leaf_4")...)),
			},
			secondNID,
		},
		{
			"4 leaves, half maxNID (not ignored)",
			false,
			[]prefixedData8{
				prefixedData8(append(minNID, []byte("leaf_1")...)),
				prefixedData8(append(secondNID, []byte("leaf_2")...)),
				prefixedData8(append(maxNID, []byte("leaf_3")...)),
				prefixedData8(append(maxNID, []byte("leaf_4")...)),
			},
			maxNID,
		},
		{
			"8 leaves, 4 maxNID (ignored)",
			true,
			[]prefixedData8{
				prefixedData8(append(minNID, []byte("leaf_1")...)),
				prefixedData8(append(secondNID, []byte("leaf_2")...)),
				prefixedData8(append(thirdNID, []byte("leaf_3")...)),
				prefixedData8(append(thirdNID, []byte("leaf_4")...)),
				prefixedData8(append(maxNID, []byte("leaf_5")...)),
				prefixedData8(append(maxNID, []byte("leaf_6")...)),
				prefixedData8(append(maxNID, []byte("leaf_7")...)),
				prefixedData8(append(maxNID, []byte("leaf_8")...)),
			},
			thirdNID,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree := New(hash, NamespaceIDSize(nidSize), IgnoreMaxNamespace(tc.ignoreMaxNamespace))
			for _, d := range tc.pushData {
				if err := tree.Push(namespace.PrefixedData(d)); err != nil {
					panic("unexpected error")
				}
			}
			r, err := tree.Root()
			require.NoError(t, err)
			gotRootMaxNID := r[tree.NamespaceSize() : tree.NamespaceSize()*2]
			if !bytes.Equal(tc.wantRootMaxNID, gotRootMaxNID) {
				t.Fatalf("Case: %v, '%v', root.Max() got: %x, want: %x", i, tc.name, gotRootMaxNID, tc.wantRootMaxNID)
			}
			for idx, d := range tc.pushData {
				proof, err := tree.ProveNamespace(d.NamespaceID())
				if err != nil {
					t.Fatalf("ProveNamespace() unexpected error: %v", err)
				}
				if gotIgnored := proof.IsMaxNamespaceIDIgnored(); gotIgnored != tc.ignoreMaxNamespace {
					t.Fatalf("Proof.IsMaxNamespaceIDIgnored() got: %v, want: %v", gotIgnored, tc.ignoreMaxNamespace)
				}
				var leaves [][]byte
				if !proof.IsEmptyProof() {
					leaves = tree.Get(d.NamespaceID())
				}
				r, err := tree.Root()
				require.NoError(t, err)
				if !proof.VerifyNamespace(hash, d.NamespaceID(), leaves, r) {
					t.Errorf("VerifyNamespace() failed on ID: %x", d.NamespaceID())
				}

				singleProof, err := tree.Prove(idx)
				if err != nil {
					t.Fatalf("ProveNamespace() unexpected error: %v", err)
				}
				r, err = tree.Root()
				require.NoError(t, err)
				if !singleProof.VerifyInclusion(hash, d.NamespaceID(), [][]byte{d.Data()}, r) {
					t.Errorf("VerifyInclusion() failed on leaves: %#v with index: %v", d, idx)
				}
				if gotIgnored := singleProof.IsMaxNamespaceIDIgnored(); gotIgnored != tc.ignoreMaxNamespace {
					t.Fatalf("Proof.IsMaxNamespaceIDIgnored() got: %v, want: %v", gotIgnored, tc.ignoreMaxNamespace)
				}
			}
		})
	}
}

func TestNodeVisitor(t *testing.T) {
	const (
		numLeaves = 4
		nidSize   = 2
		leafSize  = 6
	)
	nodeHashes := make([][]byte, 0)
	collectNodeHashes := func(hash []byte, _children ...[]byte) {
		nodeHashes = append(nodeHashes, hash)
	}

	data := generateRandNamespacedRawData(numLeaves, nidSize, leafSize)
	n := New(sha256.New(), NamespaceIDSize(nidSize), NodeVisitor(collectNodeHashes))
	for j := 0; j < numLeaves; j++ {
		if err := n.Push(data[j]); err != nil {
			t.Errorf("err: %v", err)
		}
	}
	root, err := n.Root()
	require.NoError(t, err)
	last := nodeHashes[len(nodeHashes)-1]
	if !bytes.Equal(root, last) {
		t.Fatalf("last visited node's digest does not match the tree root's.")
	}
	t.Log("printing nodes in visiting order") // postorder DFS
	for _, nodeHash := range nodeHashes {
		t.Logf("|min: %x, max: %x, digest: %x...|\n", nodeHash[:nidSize], nodeHash[nidSize:nidSize*2], nodeHash[nidSize*2:nidSize*2+3])
	}
}

func TestCustomHasher(t *testing.T) {
	type customHasher struct {
		*NmtHasher
	}

	h := customHasher{NewNmtHasher(sha256.New(), namespace.IDSize(8), true)}

	tree := New(sha256.New(), NamespaceIDSize(8), IgnoreMaxNamespace(true), CustomHasher(h))

	_, ok := tree.treeHasher.(customHasher)
	require.True(t, ok)
}

func TestNamespacedMerkleTree_ProveErrors(t *testing.T) {
	tests := []struct {
		name     string
		nidLen   int
		index    int
		pushData []namespaceDataPair
		wantErr  bool
	}{
		{"negative index", 1, -1, generateLeafData(1, 0, 10, []byte("_data")), true},
		{"too large index", 1, 11, generateLeafData(1, 0, 10, []byte("_data")), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := New(sha256.New(), NamespaceIDSize(tt.nidLen), InitialCapacity(len(tt.pushData)))
			for _, d := range tt.pushData {
				err := n.Push(namespace.PrefixedData(append(d.ID, d.Data...)))
				if err != nil {
					t.Fatalf("invalid test case: %v, error on Push(): %v", tt.name, err)
				}
			}
			for i := range tt.pushData {
				_, err := n.Prove(i)
				if err != nil {
					t.Fatalf("Prove() failed on valid index: %v, err: %v", i, err)
				}
			}
			_, err := n.Prove(tt.index)
			if (err != nil) != tt.wantErr {
				t.Errorf("Prove() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestNamespacedMerkleTree_calculateAbsenceIndex_Panic(t *testing.T) {
	const nidLen = 2
	tests := []struct {
		name     string
		nID      namespace.ID
		pushData []namespaceDataPair
	}{
		{"empty tree", []byte{0, 0}, []namespaceDataPair{}},
		{"non-empty tree with 2 leaves: ((0,0) == nID < minNID == (0,1))", []byte{0, 0}, generateLeafData(nidLen, 1, 3, []byte{})},
		{"non-empty tree with 2 leaves: ((0,3) == nID > maxNID == (0,2))", []byte{0, 3}, generateLeafData(nidLen, 1, 3, []byte{})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := New(sha256.New(), NamespaceIDSize(2))
			for _, d := range tt.pushData {
				err := n.Push(namespace.PrefixedData(append(d.ID, d.Data...)))
				assert.NoError(t, err)
			}
			shouldPanic(t,
				func() { n.calculateAbsenceIndex(tt.nID) })
		})
	}
}

// This test checks for a regression of https://github.com/celestiaorg/nmt/issues/86
func TestNMT_absenceProofOfZeroNamespace_InEmptyTree(t *testing.T) {
	tree := New(sha256.New(), NamespaceIDSize(1))
	root, err := tree.Root()
	require.NoError(t, err)
	emptyleaves, proof, err := tree.GetWithProof(namespace.ID{0})
	if err != nil {
		t.Fatalf("GetWithProof()  could not get namespace{0}. err: %v ", err)
	}
	if len(emptyleaves) != 0 {
		t.Fatalf("Get(namespace.ID{0}) should have returned no leaves but returned %v", emptyleaves)
	}
	if !proof.VerifyNamespace(sha256.New(), namespace.ID{0}, emptyleaves, root) {
		t.Fatalf("Could not verify proof of absence of namespace zero in empty tree")
	}
}

// This test checks for a regression of https://github.com/celestiaorg/nmt/issues/86
func TestNMT_forgedNamespaceEmptinessProof(t *testing.T) {
	data := [][]byte{
		append(namespace.ID{1}, []byte("leaf_0")...),
		append(namespace.ID{1}, []byte("leaf_1")...),
		append(namespace.ID{2}, []byte("leaf_2")...),
		append(namespace.ID{2}, []byte("leaf_3")...),
	}
	// Init a tree with the namespace size as well as
	// the underlying hash function:
	tree := New(sha256.New(), NamespaceIDSize(1))
	for _, d := range data {
		if err := tree.Push(d); err != nil {
			panic(fmt.Sprintf("unexpected error: %v", err))
		}
	}

	root, err := tree.Root()
	require.NoError(t, err)
	actualLeaves := tree.Get(namespace.ID{1})
	if len(actualLeaves) == 0 {
		t.Fatalf("Get(namespace.ID{1}) should have returned two leaves but returned none.")
	}

	forgedProof := Proof{
		start:                   0,
		end:                     0,
		nodes:                   [][]byte{},
		leafHash:                []byte{},
		isMaxNamespaceIDIgnored: true,
	}

	forgedProofSuccess := forgedProof.VerifyNamespace(sha256.New(), namespace.ID{1}, [][]byte{}, root)
	if forgedProofSuccess {
		t.Fatalf("Successfully verified proof that non-empty namespace was empty")
	}
}

func TestInvalidOptions(t *testing.T) {
	shouldPanic(t, func() {
		_ = New(sha256.New(), InitialCapacity(-1))
	})
	shouldPanic(t, func() {
		_ = New(sha256.New(), NamespaceIDSize(-1))
	})
	shouldPanic(t, func() {
		_ = New(sha256.New(), NamespaceIDSize(namespace.IDMaxSize+1))
	})
}

func BenchmarkComputeRoot(b *testing.B) {
	b.ReportAllocs()
	tests := []struct {
		name      string
		numLeaves int
		nidSize   int
		dataSize  int
	}{
		{"64-leaves", 64, 8, 256},
		{"128-leaves", 128, 8, 256},
		{"256-leaves", 256, 8, 256},
	}

	for _, tt := range tests {
		data := generateRandNamespacedRawData(tt.numLeaves, tt.nidSize, tt.dataSize)
		b.ResetTimer()
		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				n := New(sha256.New())
				for j := 0; j < tt.numLeaves; j++ {
					if err := n.Push(data[j]); err != nil {
						b.Errorf("err: %v", err)
					}
				}
				_, _ = n.Root()
			}
		})
	}
}

func Test_Root_RaceCondition(t *testing.T) {
	// this is very similar to: https://github.com/HuobiRDCenter/huobi_Golang/pull/9
	tree := New(sha256.New())
	_ = tree.Push([]byte("some data is good enough here"))
	numRoutines := 200
	wg := sync.WaitGroup{}
	wg.Add(numRoutines)
	for i := 0; i < numRoutines; i++ {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("race condition: panic %s", r)
				}
				wg.Done()
			}()
			_, err := tree.Root()
			require.NoError(t, err)
		}()
	}

	wg.Wait()
}

func shouldPanic(t *testing.T, f func()) {
	//nolint:errcheck
	defer func() { recover() }()
	f()
	t.Errorf("should have panicked")
}

// generates a consecutive range of leaf data
// starting from namespace zero+nsStartIdx till zero+nsEndIdx-1,
// where zero := 0*nsLen interpreted Uvarint
func generateLeafData(nsLen uint8, nsStartIdx, nsEndIdx int, data []byte) []namespaceDataPair {
	if nsEndIdx >= math.MaxUint8*int(nsLen) {
		panic(fmt.Sprintf("invalid nsEndIdx: %v, has to be < %v", nsEndIdx, 2<<(nsLen-1)))
	}

	startNS := bytes.Repeat([]byte{0x0}, int(nsLen))
	res := make([]namespaceDataPair, 0, nsEndIdx-nsStartIdx)
	for i := nsStartIdx; i < nsEndIdx; i++ {
		curNs := append([]byte(nil), startNS...)
		curNsUint, err := binary.ReadUvarint(bytes.NewReader(startNS))
		if err != nil {
			panic(err)
		}
		curNsUint = curNsUint + uint64(i)
		nsUnpadded := make([]byte, 10)
		n := binary.PutUvarint(nsUnpadded, curNsUint)
		copy(curNs[len(startNS)-n:], nsUnpadded[:n])
		res = append(res, newNamespaceDataPair(curNs, data))
	}
	return res
}

// repeats the given namespace data num times
func repeat(data []namespaceDataPair, num int) []namespaceDataPair {
	res := make([]namespaceDataPair, 0, num*len(data))
	for i := 0; i < num; i++ {
		res = append(res, data...)
	}
	return res
}

func generateRandNamespacedRawData(total int, nidSize int, leafSize int) [][]byte {
	data := make([][]byte, total)
	for i := 0; i < total; i++ {
		nid := make([]byte, nidSize)
		rand.Read(nid)
		data[i] = nid
	}
	sortByteArrays(data)
	for i := 0; i < total; i++ {
		d := make([]byte, leafSize)
		rand.Read(d)
		data[i] = append(data[i], d...)
	}

	return data
}

func sortByteArrays(src [][]byte) {
	sort.Slice(src, func(i, j int) bool { return bytes.Compare(src[i], src[j]) < 0 })
}

func TestMinMaxNamespace(t *testing.T) {
	type testCase struct {
		name    string
		tree    *NamespacedMerkleTree
		wantMin namespace.ID
		wantMax namespace.ID
	}
	testCases := []testCase{
		{
			name:    "example tree with four leaves",
			tree:    exampleNMT(1, true, 0, 0, 1, 3),
			wantMin: namespace.ID{0},
			wantMax: namespace.ID{3},
		},
		{
			name:    "example tree with eight leaves",
			tree:    exampleNMT(2, true, 1, 2, 3, 4, 5, 6, 7, 8),
			wantMin: namespace.ID{1, 1},
			wantMax: namespace.ID{8, 8},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			min, err := tc.tree.MinNamespace()
			require.NoError(t, err)
			assert.Equal(t, tc.wantMin, min)
			max, err := tc.tree.MaxNamespace()
			require.NoError(t, err)
			assert.Equal(t, tc.wantMax, max)
		})
	}
}

// exampleNMT creates a new NamespacedMerkleTree with the given namespace ID size and leaf namespace IDs. Each byte in the leavesNIDs parameter corresponds to one leaf's namespace ID. If nidSize is greater than 1, the function repeats each NID in leavesNIDs nidSize times before prepending it to the leaf data.
func exampleNMT(nidSize int, ignoreMaxNamespace bool, leavesNIDs ...byte) *NamespacedMerkleTree {
	tree := New(sha256.New(), NamespaceIDSize(nidSize), IgnoreMaxNamespace(ignoreMaxNamespace))
	for i, nid := range leavesNIDs {
		namespace := bytes.Repeat([]byte{nid}, nidSize)
		d := append(namespace, []byte(fmt.Sprintf("leaf_%d", i))...)
		if err := tree.Push(d); err != nil {
			panic(fmt.Sprintf("unexpected error: %v", err))
		}
	}
	return tree
}

func swap(slice [][]byte, i int, j int) {
	temp := slice[i]
	slice[i] = slice[j]
	slice[j] = temp
}

// Test_buildRangeProof_Err tests that buildRangeProof returns an error when the underlying tree has an invalid state e.g., leaves are not ordered by namespace ID or a leaf hash is corrupted.
func Test_buildRangeProof_Err(t *testing.T) {
	nIDList := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	nIDSize := 2

	// create a nmt, 8 leaves namespaced sequentially from 1-8
	treeWithCorruptLeafHash := exampleNMT(nIDSize, true, nIDList...)
	// corrupt a leaf hash
	treeWithCorruptLeafHash.leafHashes[4] = treeWithCorruptLeafHash.leafHashes[4][:treeWithCorruptLeafHash.NamespaceSize()]

	// create an NMT with 8 sequentially namespaced leaves, numbered from 1 to 8.
	treeWithUnorderedLeafHashes := exampleNMT(nIDSize, true, nIDList...)
	// swap the positions of the 4th and 5th leaves
	swap(treeWithUnorderedLeafHashes.leaves, 4, 5)
	swap(treeWithUnorderedLeafHashes.leafHashes, 4, 5)

	validTree := exampleNMT(nIDSize, true, nIDList...)

	tests := []struct {
		name                 string
		tree                 *NamespacedMerkleTree
		proofStart, proofEnd int
		wantErr              bool
		errType              error
	}{
		{"corrupt leaf hash", treeWithCorruptLeafHash, 4, 5, true, ErrInvalidNodeLen},
		{"unordered leaf hashes: the out of order range", treeWithUnorderedLeafHashes, 4, 5, true, ErrUnorderedSiblings},
		{"unordered leaf hashes: the first leaf", treeWithUnorderedLeafHashes, 1, 2, true, ErrUnorderedSiblings}, // for a tree with an unordered set of leaves, the buildRangeProof function  should produce an error for any input range,
		// not just the corrupted range.
		{"unordered leaf hashes: the last leaf", treeWithUnorderedLeafHashes, 7, 8, true, ErrUnorderedSiblings}, // for a tree with an unordered set of leaves, the buildRangeProof function  should produce an error for any input range,
		// not just the corrupted range.
		{"invalid proof range: start > end", validTree, 5, 4, true, ErrInvalidRange},
		{"invalid proof range: start = end", validTree, 5, 5, true, ErrInvalidRange},
		{"invalid proof range: start < 0", validTree, -1, 4, true, ErrInvalidRange},
		{"invalid proof range: end > number of leaves", validTree, 0, len(validTree.leaves) + 1, true, ErrInvalidRange},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.tree.buildRangeProof(tt.proofStart, tt.proofEnd)
			assert.Equal(t, tt.wantErr, err != nil)
			if tt.wantErr {
				assert.True(t, errors.Is(err, tt.errType))
			}
		})
	}
}

// Test_ProveRange_Err tests that ProveRange returns an error when the underlying tree has an invalid state e.g., leaves are not ordered by namespace ID or a leaf hash is corrupted.
func Test_ProveRange_Err(t *testing.T) {
	// create an NMT with 8 sequentially namespaced leaves, numbered from 1 to 8.
	treeWithCorruptLeafHash := exampleNMT(2, true, 1, 2, 3, 4, 5, 6, 7, 8)
	// corrupt a leaf hash
	treeWithCorruptLeafHash.leafHashes[4] = treeWithCorruptLeafHash.leafHashes[4][:treeWithCorruptLeafHash.NamespaceSize()]

	// create an NMT with 8 sequentially namespaced leaves, numbered from 1 to 8.
	treeWithUnorderedLeafHashes := exampleNMT(2, true, 1, 2, 3, 4, 5, 6, 7, 8)
	// swap the positions of the 4th and 5th leaves
	swap(treeWithUnorderedLeafHashes.leaves, 4, 5)
	swap(treeWithUnorderedLeafHashes.leafHashes, 4, 5)

	tests := []struct {
		name                 string
		tree                 *NamespacedMerkleTree
		proofStart, proofEnd int
		wantErr              bool
		errType              error
	}{
		{"corrupt leaf hash", treeWithCorruptLeafHash, 4, 5, true, ErrInvalidNodeLen},
		{"unordered leaf hashes: the out of order leaf", treeWithUnorderedLeafHashes, 4, 5, true, ErrUnorderedSiblings},
		{"unordered leaf hashes: first leaf", treeWithUnorderedLeafHashes, 1, 2, true, ErrUnorderedSiblings}, // for a tree with an unordered set of leaves, the ProveRange method  should produce an error for any input range,
		// not just the corrupted range.
		{"unordered leaf hashes: last leaf", treeWithUnorderedLeafHashes, 7, 8, true, ErrUnorderedSiblings}, // for a tree with an unordered set of leaves, the ProveRange method  should produce an error for any input range,
		// not just the corrupted range.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.tree.ProveRange(tt.proofStart, tt.proofEnd)
			assert.Equal(t, tt.wantErr, err != nil)
			if tt.wantErr {
				assert.True(t, errors.Is(err, tt.errType))
			}
		})
	}
}

// The Test_ProveNamespace_Err function tests that ProveNamespace returns an error when the underlying tree is in an invalid state, such as when the leaves are not ordered by namespace ID or when a leaf hash is corrupt.
func Test_ProveNamespace_Err(t *testing.T) {
	// create an NMT with 8 sequentially namespaced leaves, numbered from 1 to 8.
	treeWithCorruptLeafHash := exampleNMT(2, true, 1, 2, 3, 4, 5, 6, 7, 8)
	// corrupt a leaf hash
	treeWithCorruptLeafHash.leafHashes[4] = treeWithCorruptLeafHash.leafHashes[4][:treeWithCorruptLeafHash.NamespaceSize()]

	// create an NMT with 8 sequentially namespaced leaves, numbered from 1 to 8.
	treeWithUnorderedLeafHashes := exampleNMT(2, true, 1, 2, 3, 4, 5, 6, 7, 8)
	// swap the positions of the 4th and 5th leaves
	swap(treeWithUnorderedLeafHashes.leaves, 4, 5)
	swap(treeWithUnorderedLeafHashes.leafHashes, 4, 5)

	tests := []struct {
		name    string
		tree    *NamespacedMerkleTree
		nID     namespace.ID
		wantErr bool
		errType error
	}{
		{"corrupt leaf hash", treeWithCorruptLeafHash, namespace.ID{5, 5}, true, ErrInvalidNodeLen},
		{"unordered leaf hashes: the queried namespace falls in the corrupted range", treeWithUnorderedLeafHashes, namespace.ID{5, 5}, true, ErrUnorderedSiblings},
		{"unordered leaf hashes: query for the first namespace", treeWithUnorderedLeafHashes, namespace.ID{1, 1}, true, ErrUnorderedSiblings}, // for a tree with an unordered set of leaves,
		// the ProveNamespace method  should produce an error for any input namespace ID.
		{"unordered leaf hashes: query for the last namespace", treeWithUnorderedLeafHashes, namespace.ID{8, 8}, true, ErrUnorderedSiblings}, // for a tree with an unordered set of leaves,
		// the ProveNamespace method  should produce an error for any namespace ID.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.tree.ProveNamespace(tt.nID)
			assert.Equal(t, tt.wantErr, err != nil)
			if tt.wantErr {
				assert.True(t, errors.Is(err, tt.errType))
			}
		})
	}
}

// Test_Root_Error tests that the Root method returns an error when the underlying tree is in an invalid state, such as when the leaves are not ordered by namespace ID or when a leaf is corrupt.
func Test_Root_Error(t *testing.T) {
	// create an NMT with 8 sequentially namespaced leaves, numbered from 1 to 8.
	treeWithCorruptLeafHash := exampleNMT(2, true, 1, 2, 3, 4, 5, 6, 7, 8)
	// corrupt a leaf hash
	treeWithCorruptLeafHash.leafHashes[4] = treeWithCorruptLeafHash.leafHashes[4][:treeWithCorruptLeafHash.NamespaceSize()-1]

	// create an NMT with 8 sequentially namespaced leaves, numbered from 1 to 8.
	treeWithUnorderedLeaves := exampleNMT(2, true, 1, 2, 3, 4, 5, 6, 7, 8)
	// swap the positions of the 4th and 5th leaves
	swap(treeWithUnorderedLeaves.leaves, 4, 5)
	swap(treeWithUnorderedLeaves.leafHashes, 4, 5)

	tests := []struct {
		name    string
		tree    *NamespacedMerkleTree
		wantErr bool
		errType error
	}{
		{"corrupt leaf hash", treeWithCorruptLeafHash, true, ErrInvalidNodeLen},
		{"unordered leaf hashes", treeWithUnorderedLeaves, true, ErrUnorderedSiblings},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.tree.Root()
			assert.Equal(t, tt.wantErr, err != nil)
			if tt.wantErr {
				assert.True(t, errors.Is(err, tt.errType))
			}
		})
	}
}

// Test_computeRoot_Error tests that the computeRoot method returns an error when the underlying tree is in an invalid state, such as when the leaves are not ordered by namespace ID or when a leaf is corrupt.
func Test_computeRoot_Error(t *testing.T) {
	nIDSize := 2
	nIDList := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	// create an NMT with 8 sequentially namespaced leaves, numbered from 1 to 8.
	treeWithCorruptLeafHash := exampleNMT(nIDSize, true, nIDList...)
	// corrupt a leaf hash
	treeWithCorruptLeafHash.leafHashes[4] = treeWithCorruptLeafHash.leafHashes[4][:treeWithCorruptLeafHash.NamespaceSize()-1]

	// create an NMT with 8 sequentially namespaced leaves, numbered from 1 to 8.
	treeWithUnorderedLeaves := exampleNMT(nIDSize, true, nIDList...)
	// swap the positions of the 4th and 5th leaves
	swap(treeWithUnorderedLeaves.leaves, 4, 5)
	swap(treeWithUnorderedLeaves.leafHashes, 4, 5)

	// create an NMT with 8 sequentially namespaced leaves, numbered from 1 to 8.
	validTree := exampleNMT(nIDSize, true, nIDList...)

	tests := []struct {
		name       string
		tree       *NamespacedMerkleTree
		start, end int
		wantErr    bool
		errType    error
	}{
		{"invalid tree with corrupt leaf hash. Query: the entire tree", treeWithCorruptLeafHash, 0, 7, true, ErrInvalidNodeLen},
		{"invalid tree with corrupt leaf. Query: from the corrupt node until the end of the tree", treeWithCorruptLeafHash, 4, 7, true, ErrInvalidNodeLen},
		{"invalid tree with corrupt leaf. Query: the corrupt node and the node to its left", treeWithCorruptLeafHash, 3, 5, true, ErrInvalidNodeLen},
		{"invalid tree with unordered leaves. Query: the entire tree", treeWithUnorderedLeaves, 0, 7, true, ErrUnorderedSiblings},
		{"invalid tree with unordered leaves. Query: the unordered portion", treeWithUnorderedLeaves, 4, 6, true, ErrUnorderedSiblings},
		{"invalid tree with unordered leaves. Query: a portion of the tree containing the unordered leaves", treeWithUnorderedLeaves, 3, 7, true, ErrUnorderedSiblings},
		{"valid tree. Query: start < 0", validTree, -1, 1, true, ErrInvalidRange},
		{"valid tree. Query: start > end", validTree, 3, 1, true, ErrInvalidRange},
		{"valid tree. Query: end > total number of leaves", validTree, 3, len(validTree.leaves) + 1, true, ErrInvalidRange},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.tree.computeRoot(tt.start, tt.end)
			assert.Equal(t, tt.wantErr, err != nil)
			if tt.wantErr {
				assert.True(t, errors.Is(err, tt.errType))
			}
		})
	}
}

// Test_MinMaxNamespace_Err tests that the MinNamespace and MaxNamespace methods return an error when the underlying tree is in an invalid state, such as when the leaves are not ordered by namespace ID or when a leaf is corrupt.
func Test_MinMaxNamespace_Err(t *testing.T) {
	// create an NMT with 8 sequentially namespaced leaves, numbered from 1 to 8.
	treeWithCorruptLeafHash := exampleNMT(2, true, 1, 2, 3, 4, 5, 6, 7, 8)
	// corrupt a leaf hash
	treeWithCorruptLeafHash.leafHashes[4] = treeWithCorruptLeafHash.leafHashes[4][:treeWithCorruptLeafHash.NamespaceSize()-1]

	// create an NMT with 8 sequentially namespaced leaves, numbered from 1 to 8.
	treeWithUnorderedLeaves := exampleNMT(2, true, 1, 2, 3, 4, 5, 6, 7, 8)
	// swap the positions of the 4th and 5th leaves
	swap(treeWithUnorderedLeaves.leaves, 4, 5)
	swap(treeWithUnorderedLeaves.leafHashes, 4, 5)

	tests := []struct {
		name    string
		tree    *NamespacedMerkleTree
		wantErr bool
		errType error
	}{
		{"corrupt leaf hash", treeWithCorruptLeafHash, true, ErrInvalidNodeLen},
		{"unordered leaves", treeWithUnorderedLeaves, true, ErrUnorderedSiblings},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.tree.MinNamespace()
			assert.Equal(t, tt.wantErr, err != nil)
			if tt.wantErr {
				assert.True(t, errors.Is(err, tt.errType))
			}

			_, err = tt.tree.MaxNamespace()
			assert.Equal(t, tt.wantErr, err != nil)
			if tt.wantErr {
				assert.True(t, errors.Is(err, tt.errType))
			}
		})
	}
}

// TestProveNamespace_MaxNamespace checks the output of the ProveNamespace method when queried for the maximum namespace ID.
func TestProveNamespace_MaxNamespace(t *testing.T) {
	nidSize := 1
	MaxNS := byte(math.MaxUint8)
	tests := []struct {
		name         string
		nIDList      []byte
		isEmptyProof bool
	}{
		{"tree with no leaf", []byte{}, true},
		{"tree with one leaf with MaxNS", []byte{MaxNS}, false},
		{"tree with two leaves, the right leaf has MaxNS", []byte{1, MaxNS}, true},
		{"tree with four leaves, the right half has MaxNS", []byte{1, 2, MaxNS, MaxNS}, true},
		{"tree with 8 leaves, the right half has MaxNS", []byte{1, 2, 3, 4, MaxNS, MaxNS, MaxNS, MaxNS}, true},
	}
	for _, tt := range tests {
		tree := exampleNMT(nidSize, true, tt.nIDList...)
		t.Run(tt.name, func(t *testing.T) {
			proof, err := tree.ProveNamespace(namespace.ID{MaxNS})
			assert.NoError(t, err)
			assert.Equal(t, tt.isEmptyProof, proof.IsEmptyProof())
		})
	}
}

// TestEmptyRoot_NMT tests that the empty root of a tree is the same as the empty root of a hasher with the same configuration.
func TestEmptyRoot_NMT(t *testing.T) {
	nIDSzie := 1
	ignoreMaxNS := true
	nIDList := []byte{1, 2, 3, 4}

	// create a nmt using the above configs
	tree := New(sha256.New(), NamespaceIDSize(nIDSzie), IgnoreMaxNamespace(ignoreMaxNS))
	for i, nid := range nIDList {
		namespace := bytes.Repeat([]byte{nid}, nIDSzie)
		d := append(namespace, []byte(fmt.Sprintf("leaf_%d", i))...)
		if err := tree.Push(d); err != nil {
			panic(fmt.Sprintf("unexpected error: %v", err))
		}
	}
	// calculate the empty root by accessing the `Hasher` field of the tree
	expectedEmptyRoot := tree.treeHasher.EmptyRoot()

	// create  a hasher identical to the one used for the tree
	hasher := NewNmtHasher(sha256.New(), namespace.IDSize(nIDSzie), ignoreMaxNS)
	gotEmptyRoot := hasher.EmptyRoot()

	assert.True(t, bytes.Equal(gotEmptyRoot, expectedEmptyRoot))
}

func TestForcedOutOfOrderNamespacedMerkleTree(t *testing.T) {
	data := [][]byte{
		append(namespace.ID{0}, []byte("leaf_0")...),
		append(namespace.ID{2}, []byte("leaf_1")...),
		append(namespace.ID{1}, []byte("leaf_2")...),
		append(namespace.ID{1}, []byte("leaf_3")...),
	}
	nidSize := 1
	tree := New(sha256.New(), NamespaceIDSize(nidSize))

	for _, d := range data {
		err := tree.ForceAddLeaf(d)
		assert.NoError(t, err)
	}
}
