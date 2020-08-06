package nmt

import (
	"bytes"
	"crypto"
	_ "crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"testing"

	"github.com/lazyledger/nmt/defaulthasher"
	"github.com/lazyledger/nmt/namespace"
)

const (
	LeafPrefix = defaulthasher.LeafPrefix
	NodePrefix = defaulthasher.NodePrefix
)

func TestFromNamespaceAndData(t *testing.T) {
	tests := []struct {
		name      string
		namespace []byte
		data      []byte
		want      namespace.PrefixedData
	}{
		0: {"simple case", []byte("namespace1"), []byte("data1"), namespace.NewPrefixedData(10, append([]byte("namespace1"), []byte("data1")...))},
		1: {"simpler case", []byte("1"), []byte("d"), namespace.NewPrefixedData(1, append([]byte("1"), []byte("d")...))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := namespace.PrefixedDataFrom(tt.namespace, tt.data); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PrefixedDataFrom() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNamespacedMerkleTree_Push(t *testing.T) {
	tests := []struct {
		name    string
		data    namespace.PrefixedData
		wantErr bool
	}{
		{"1st push: always OK", namespace.PrefixedDataFrom([]byte{0, 0, 0}, []byte("dummy data")), false},
		{"push with same namespace: OK", namespace.PrefixedDataFrom([]byte{0, 0, 0}, []byte("dummy data")), false},
		{"push with greater namespace: OK", namespace.PrefixedDataFrom([]byte{0, 0, 1}, []byte("dummy data")), false},
		{"push with smaller namespace: Err", namespace.PrefixedDataFrom([]byte{0, 0, 0}, []byte("dummy data")), true},
		{"push with same namespace: Ok", namespace.PrefixedDataFrom([]byte{0, 0, 1}, []byte("dummy data")), false},
		{"push with greater namespace: Ok", namespace.PrefixedDataFrom([]byte{1, 0, 0}, []byte("dummy data")), false},
		{"push with smaller namespace: Err", namespace.PrefixedDataFrom([]byte{0, 0, 1}, []byte("dummy data")), true},
		{"push with smaller namespace: Err", namespace.PrefixedDataFrom([]byte{0, 0, 0}, []byte("dummy data")), true},
		{"push with smaller namespace: Err", namespace.PrefixedDataFrom([]byte{0, 1, 0}, []byte("dummy data")), true},
		{"push with same as last namespace: OK", namespace.PrefixedDataFrom([]byte{1, 0, 0}, []byte("dummy data")), false},
		{"push with greater as last namespace: OK", namespace.PrefixedDataFrom([]byte{1, 1, 0}, []byte("dummy data")), false},
		// note this tests for another kind of error: ErrMismatchedNamespaceSize
		{"push with wrong namespace size: Err", namespace.PrefixedDataFrom([]byte{1, 1, 0, 0}, []byte("dummy data")), true},
	}
	n := New(defaulthasher.New(uint8(3), crypto.SHA256))
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
	// TODO: add in more realistic test-vectors
	zeroNs := []byte{0, 0, 0}
	onesNS := []byte{1, 1, 1}
	leaf := []byte("leaf1")
	leafHash := sum(crypto.SHA256, []byte{LeafPrefix}, leaf)
	zeroFlaggedLeaf := append(append(zeroNs, zeroNs...), leafHash...)
	oneFlaggedLeaf := append(append(onesNS, onesNS...), leafHash...)
	twoZeroLeafsRoot := sum(crypto.SHA256, []byte{NodePrefix}, zeroFlaggedLeaf, zeroFlaggedLeaf)
	diffNSLeafsRoot := sum(crypto.SHA256, []byte{NodePrefix}, zeroFlaggedLeaf, oneFlaggedLeaf)
	emptyRoot := crypto.SHA256.New().Sum(nil)

	tests := []struct {
		name       string
		nidLen     uint8
		pushedData []namespace.PrefixedData
		wantMinNs  namespace.ID
		wantMaxNs  namespace.ID
		wantRoot   []byte
	}{
		// default empty root according to base case:
		// https://github.com/lazyledger/lazyledger-specs/blob/master/specs/data_structures.md#namespace-merkle-tree
		{"Empty", 3, nil, zeroNs, zeroNs, emptyRoot},
		{"One leaf", 3, []namespace.PrefixedData{namespace.PrefixedDataFrom(zeroNs, leaf)}, zeroNs, zeroNs, leafHash},
		{"Two leaves", 3, []namespace.PrefixedData{namespace.PrefixedDataFrom(zeroNs, leaf), namespace.PrefixedDataFrom(zeroNs, leaf)}, zeroNs, zeroNs, twoZeroLeafsRoot},
		{"Two leaves diff namespaces", 3, []namespace.PrefixedData{namespace.PrefixedDataFrom(zeroNs, leaf), namespace.PrefixedDataFrom(onesNS, leaf)}, zeroNs, onesNS, diffNSLeafsRoot},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := New(defaulthasher.New(tt.nidLen, crypto.SHA256))
			for _, d := range tt.pushedData {
				if err := n.Push(d); err != nil {
					t.Errorf("Push() error = %v, expected no error", err)
				}
			}
			root := n.Root()
			gotMinNs, gotMaxNs, gotRoot := root.Min(), root.Max(), root.Hash()
			if !reflect.DeepEqual(gotMinNs, tt.wantMinNs) {
				t.Errorf("Root() gotMinNs = %v, want %v", gotMinNs, tt.wantMinNs)
			}
			if !reflect.DeepEqual(gotMaxNs, tt.wantMaxNs) {
				t.Errorf("Root() gotMaxNs = %v, want %v", gotMaxNs, tt.wantMaxNs)
			}
			if !reflect.DeepEqual(gotRoot, tt.wantRoot) {
				t.Errorf("Root() gotRoot = %v, want %v", gotRoot, tt.wantRoot)
			}
		})
	}
}

func TestNamespacedMerkleTree_ProveNamespace_Ranges_And_Verify(t *testing.T) {
	tests := []struct {
		name           string
		nidLen         uint8
		pushData       []namespace.PrefixedData
		proveNID       namespace.ID
		wantProofStart int
		wantProofEnd   int
		wantFound      bool
	}{
		{"found", 1,
			generateLeafData(1, 0, 1, []byte("_data")),
			[]byte{0},
			0, 1,
			true},
		{"not found", 1,
			generateLeafData(1, 0, 1, []byte("_data")),
			[]byte{1},
			0, 0,
			false},
		{"two leaves and found", 1,
			append(generateLeafData(1, 0, 1, []byte("_data")), generateLeafData(1, 1, 2, []byte("_data"))...),
			[]byte{1},
			1, 2,
			true},
		{"two leaves and found2", 1,
			repeat(generateLeafData(1, 0, 1, []byte("_data")), 2),
			[]byte{1},
			0, 0, false},
		{"three leaves and found", 1,
			append(repeat(generateLeafData(1, 0, 1, []byte("_data")), 2), generateLeafData(1, 1, 2, []byte("_data"))...),
			[]byte{1},
			2, 3,
			true},
		{"three leaves and not found but with range", 2,
			append(repeat(generateLeafData(2, 0, 1, []byte("_data")), 2), makeLeafData([]byte{1, 1}, []byte("_data"))),
			[]byte{0, 1},
			2, 3,
			false},
		{"three leaves and not found but within range", 2,
			append(repeat(generateLeafData(2, 0, 1, []byte("_data")), 2), makeLeafData([]byte{1, 1}, []byte("_data"))),
			[]byte{0, 1},
			2, 3,
			false},
		{"5 leaves and not found but within range (00, 01, 02, 03, <1,0>, 11)", 2,
			append(generateLeafData(2, 0, 4, []byte("_data")), makeLeafData([]byte{1, 1}, []byte("_data"))),
			[]byte{1, 0},
			4, 5,
			false},
		// In the cases (nID < minNID) or (maxNID < nID) we do not generate any proof
		// and the (minNS, maxNs, root) should be indication enough that nID is not in that range.
		{"4 leaves, not found and nID < minNID", 2,
			[]namespace.PrefixedData{namespace.NewPrefixedData(2, []byte("01_data")), namespace.NewPrefixedData(2, []byte("01_data")), namespace.NewPrefixedData(2, []byte("01_data")), namespace.NewPrefixedData(2, []byte("11_data"))},
			[]byte("00"),
			0, 0,
			false},
		{"4 leaves, not found and nID > maxNID ", 2,
			[]namespace.PrefixedData{namespace.NewPrefixedData(2, []byte("00_data")), namespace.NewPrefixedData(2, []byte("00_data")), namespace.NewPrefixedData(2, []byte("01_data")), namespace.NewPrefixedData(2, []byte("01_data"))},
			[]byte("11"),
			0, 0,
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defaultHasher := defaulthasher.New(tt.nidLen, crypto.SHA256)
			n := New(defaultHasher)
			for _, d := range tt.pushData {
				err := n.Push(d)
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
			gotChecksOut := gotProof.VerifyNamespace(defaultHasher, tt.proveNID, gotGetLeaves, n.Root())
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
					gotChecksOut := gotSingleProof.VerifyInclusion(defaultHasher, data, n.Root())
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

func TestNamespacedMerkleTree_ProveErrors(t *testing.T) {
	tests := []struct {
		name      string
		nidLen    uint8
		index     int
		pushData  []namespace.PrefixedData
		wantErr   bool
		wantPanic bool
	}{
		{"negative index", 1, -1, generateLeafData(1, 0, 10, []byte("_data")), false, true},
		{"too large index", 1, 11, generateLeafData(1, 0, 10, []byte("_data")), true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defaultHasher := defaulthasher.New(tt.nidLen, crypto.SHA256)
			n := New(defaultHasher)
			for _, d := range tt.pushData {
				err := n.Push(d)
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
			if tt.wantPanic {
				shouldPanic(t, func() {
					_, err := n.Prove(tt.index)
					if (err != nil) != tt.wantErr {
						t.Errorf("Prove() error = %v, wantErr %v", err, tt.wantErr)
						return
					}
				})
			} else {
				_, err := n.Prove(tt.index)
				if (err != nil) != tt.wantErr {
					t.Errorf("Prove() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}
		})
	}
}

func TestNamespacedMerkleTree_calculateAbsenceIndex_Panic(t *testing.T) {
	const nidLen = 2
	tests := []struct {
		name     string
		nID      namespace.ID
		pushData []namespace.PrefixedData
	}{
		{"((0,0) == nID < minNID == (0,1))", []byte{0, 0}, generateLeafData(nidLen, 1, 3, []byte{})},
		{"((0,3) == nID > maxNID == (0,2))", []byte{0, 3}, generateLeafData(nidLen, 1, 3, []byte{})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := New(defaulthasher.New(2, crypto.SHA256))
			shouldPanic(t,
				func() { n.calculateAbsenceIndex(tt.nID) })
		})
	}
}

func shouldPanic(t *testing.T, f func()) {
	//nolint:errcheck
	defer func() { recover() }()
	f()
	t.Errorf("should have panicked")
}

func makeLeafData(ns []byte, data []byte) namespace.PrefixedData {
	if len(ns) > math.MaxUint8 {
		panic("namespace too large")
	}
	return namespace.NewPrefixedData(uint8(len(ns)), append(ns, data...))
}

// generates a consecutive range of leaf data
// starting from namespace zero+start till zero+end,
// where zero := 0*nsLen interpreted Uvarint
func generateLeafData(nsLen uint8, nsStartIdx, nsEndIdx int, data []byte) []namespace.PrefixedData {
	if nsEndIdx >= math.MaxUint8*int(nsLen) {
		panic(fmt.Sprintf("invalid nsEndIdx: %v, has to be < %v", nsEndIdx, 2<<(nsLen-1)))
	}

	startNS := bytes.Repeat([]byte{0x0}, int(nsLen))
	res := make([]namespace.PrefixedData, 0, nsEndIdx-nsStartIdx)
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
		res = append(res, namespace.NewPrefixedData(nsLen, append(curNs, data...)))
	}
	return res
}

// repeats the given namespace data num times
func repeat(data []namespace.PrefixedData, num int) []namespace.PrefixedData {
	res := make([]namespace.PrefixedData, 0, num*len(data))
	for i := 0; i < num; i++ {
		res = append(res, data...)
	}
	return res
}

func sum(hash crypto.Hash, data ...[]byte) []byte {
	h := hash.New()
	for _, d := range data {
		//nolint:errcheck
		h.Write(d)
	}

	return h.Sum(nil)
}
