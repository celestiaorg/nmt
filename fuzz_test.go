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

// FuzzProveVerifyNamespace builds trees from randomly generated namespaces and
// leaf data, then checks that namespace proofs and inclusion proofs for every
// namespace verify against the root. The fuzzed seed drives a deterministic
// random generator so that every failure is reproducible from its corpus
// entry. Run with: go test -fuzz=FuzzProveVerifyNamespace
func FuzzProveVerifyNamespace(f *testing.F) {
	if testing.Short() {
		f.Skip("FuzzProveVerifyNamespace skipped in short mode.")
	}
	for seed := int64(0); seed < 5; seed++ {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, seed int64) {
		rng := rand.New(rand.NewSource(seed))
		for _, nsSize := range []int{8, 16, 32} {
			proveAndVerifyNamespaces(t, rng, nsSize)
		}
	})
}

func proveAndVerifyNamespaces(t *testing.T, rng *rand.Rand, nsSize int) {
	nidDataMap, sortedKeys := makeRandDataAndSortedKeys(rng, nsSize)
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
				t.Fatalf("error on Prove(%v): %v", i, err)
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

// makeRandDataAndSortedKeys generates a map of random namespaces to lists of
// leaves (each leaf prefixed with its namespace), plus the namespace keys in
// ascending order. Some namespaces are left empty so that proofs of absence
// get exercised.
func makeRandDataAndSortedKeys(rng *rand.Rand, nsSize int) (map[string][][]byte, []string) {
	// The ranges are kept small enough that a single fuzz iteration completes
	// in milliseconds; per-leaf proving is quadratic in the total leaf count,
	// and iterations slower than a few seconds trip the fuzzer's hang
	// detector.
	const (
		minNumberOfNamespaces = 4
		maxNumberOfNamespaces = 16

		minElementsPerNamespace = 0
		maxElementsPerNamespace = 32

		maxElementSize = 64

		emptyNamespaceProbability = 0.15
	)

	numNamespaces := randRange(rng, minNumberOfNamespaces, maxNumberOfNamespaces)
	nidDataMap := make(map[string][][]byte, numNamespaces)
	for len(nidDataMap) < numNamespaces {
		ns := make([]byte, nsSize)
		rng.Read(ns)
		if _, ok := nidDataMap[string(ns)]; ok {
			continue
		}
		var leaves [][]byte
		if rng.Float64() >= emptyNamespaceProbability {
			leaves = make([][]byte, randRange(rng, minElementsPerNamespace, maxElementsPerNamespace))
			for i := range leaves {
				leaf := make([]byte, nsSize+rng.Intn(maxElementSize+1))
				copy(leaf, ns)
				rng.Read(leaf[nsSize:])
				leaves[i] = leaf
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

// randRange returns a random int in the inclusive range [low, high].
func randRange(rng *rand.Rand, low, high int) int {
	return low + rng.Intn(high-low+1)
}
