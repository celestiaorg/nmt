package nmt_test

import (
	"crypto/sha256"
	"math/rand"
	"reflect"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/nmt"
	"github.com/celestiaorg/nmt/namespace"
)

// FuzzProveVerifyNamespace builds a tree from namespaces and leaf data parsed
// out of the raw fuzz input, then checks that namespace proofs and inclusion
// proofs for every namespace verify against the root. Parsing the input bytes
// directly (rather than fuzzing a PRNG seed) lets the coverage-guided fuzzer
// mutate the actual tree structure and leaf data.
// Run with: go test -fuzz=FuzzProveVerifyNamespace
func FuzzProveVerifyNamespace(f *testing.F) {
	if testing.Short() {
		f.Skip("FuzzProveVerifyNamespace skipped in short mode.")
	}
	// Seed corpus: deterministic pseudo-random inputs covering every
	// namespace size, plus the empty-tree edge case.
	f.Add([]byte{})
	rng := rand.New(rand.NewSource(1))
	for sizeIdx := 0; sizeIdx < 3; sizeIdx++ {
		for _, inputLen := range []int{64, 2048, 16384} {
			seed := make([]byte, inputLen)
			rng.Read(seed)
			seed[0] = byte(sizeIdx)
			f.Add(seed)
		}
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) == 0 {
			return
		}
		nsSizes := []int{8, 16, 32}
		nsSize := nsSizes[int(input[0])%len(nsSizes)]
		proveAndVerifyNamespaces(t, input[1:], nsSize)
	})
}

func proveAndVerifyNamespaces(t *testing.T, input []byte, nsSize int) {
	nidDataMap, sortedKeys := makeNsDataAndSortedKeys(input, nsSize)
	t.Logf("Generated %v namespaces for size: %v ...", len(nidDataMap), nsSize)
	hash := sha256.New()
	tree := nmt.New(hash, nmt.NamespaceIDSize(nsSize))

	// push data in order:
	for _, ns := range sortedKeys {
		leafDataList := nidDataMap[ns]
		for _, d := range leafDataList {
			err := tree.Push(d)
			if err != nil {
				t.Fatalf("error on Push(): %v", err)
			}
		}
	}

	treeRoot, err := tree.Root()
	require.NoError(t, err)
	nonEmptyNsCount := 0
	leafIdx := 0
	for _, ns := range sortedKeys {
		nid := namespace.ID(ns)
		data := tree.Get(nid)
		proof, err := tree.ProveNamespace(nid)
		if err != nil {
			t.Fatalf("error on ProveNamespace(%x): %v", ns, err)
		}

		if ok := proof.VerifyNamespace(hash, nid, data, treeRoot); !ok {
			t.Fatalf("expected VerifyNamespace() == true")
		}

		// some sanity checks:
		items := nidDataMap[ns]
		if len(items) != len(data) {
			t.Fatalf("returned number of items didn't match pushed number of items")
		}
		for i := 0; i < len(items); i++ {
			if !reflect.DeepEqual(items[i], data[i]) {
				t.Fatalf("returned data didn't match pushed data")
			}
			singleItemProof, err := tree.Prove(leafIdx)
			if err != nil {
				t.Fatalf("error on Prove(%v): %v", leafIdx, err)
			}
			if ok := singleItemProof.VerifyInclusion(hash, data[i][:nsSize], [][]byte{data[i][nsSize:]}, treeRoot); !ok {
				t.Fatalf("expected VerifyInclusion() == true; data = %#v; proof = %#v", data[i], singleItemProof)
			}
			leafIdx++
		}

		isSingleLeaf := proof.End()-proof.Start() == 1
		if len(data) == 0 && !isSingleLeaf &&
			(proof.IsOfAbsence() || (!proof.IsOfAbsence() && proof.IsNonEmptyRange())) {
			t.Errorf("expected proof of absence, or, an non-empty range proof, or, a single empty leaf for ns %x", ns)
		}
		if !proof.IsNonEmptyRange() && proof.IsOfAbsence() {
			t.Fatalf("empty range can't be a proof of absence for a namespace")
		}

		if len(data) != 0 {
			emptyProof := nmt.NewEmptyRangeProof(false)
			if emptyProof.VerifyNamespace(hash, nid, data, treeRoot) {
				t.Fatalf("empty range proof on non-empty data verified to true")
			}
			nonEmptyNsCount++
		}
	}
	t.Logf("... with %v of %v namespaces non-empty.", nonEmptyNsCount, len(sortedKeys))
}

// makeNsDataAndSortedKeys parses the fuzz input into a map of namespaces to
// lists of leaves (each leaf prefixed with its namespace), plus the namespace
// keys in ascending order. Namespaces with a count byte below
// emptyNamespaceThreshold are left empty so that proofs of absence get
// exercised.
func makeNsDataAndSortedKeys(input []byte, nsSize int) (map[string][][]byte, []string) {
	// The caps keep a single fuzz iteration in the milliseconds range;
	// per-leaf proving is quadratic in the total leaf count, and iterations
	// slower than a few seconds trip the fuzzer's hang detector.
	const (
		maxNumberOfNamespaces   = 16
		maxElementsPerNamespace = 32
		maxElementSize          = 64

		// ~15% of count bytes leave the namespace empty.
		emptyNamespaceThreshold = 40
	)

	r := &byteReader{data: input}
	nidDataMap := make(map[string][][]byte)
	for len(nidDataMap) < maxNumberOfNamespaces && r.remaining() > 0 {
		ns := r.read(nsSize)
		if _, ok := nidDataMap[string(ns)]; ok {
			continue
		}
		var leaves [][]byte
		if countByte := r.readByte(); countByte >= emptyNamespaceThreshold {
			numLeaves := 1 + int(countByte)%maxElementsPerNamespace
			leaves = make([][]byte, 0, numLeaves)
			for i := 0; i < numLeaves; i++ {
				payloadLen := int(r.readByte()) % (maxElementSize + 1)
				leaf := make([]byte, 0, nsSize+payloadLen)
				leaf = append(leaf, ns...)
				leaf = append(leaf, r.read(payloadLen)...)
				leaves = append(leaves, leaf)
			}
		}
		nidDataMap[string(ns)] = leaves
	}

	keys := make([]string, 0, len(nidDataMap))
	for k := range nidDataMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return nidDataMap, keys
}

// byteReader hands out chunks of the fuzz input, zero-padding once the input
// is exhausted so parsing never fails mid-structure.
type byteReader struct {
	data []byte
}

func (r *byteReader) remaining() int {
	return len(r.data)
}

func (r *byteReader) readByte() byte {
	return r.read(1)[0]
}

func (r *byteReader) read(n int) []byte {
	out := make([]byte, n)
	m := copy(out, r.data)
	r.data = r.data[m:]
	return out
}
