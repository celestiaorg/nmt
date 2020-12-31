package nmt_test

import (
	"crypto/sha256"
	"reflect"
	"sort"
	"testing"

	"github.com/google/gofuzz"
	"github.com/lazyledger/nmt"
	"github.com/lazyledger/nmt/namespace"
)

func TestFuzzProveVerifyNameSpace(t *testing.T) {
	if testing.Short() {
		t.Skip("TestFuzzProveVerifyNameSpace skipped in short mode.")
	}
	var (
		minNumberOfNamespaces = 4
		maxNumberOfNamespaces = 64

		minElementsPerNamespace = 0
		maxElementsPerNamespace = 128

		emptyNamespaceProbability = 0.15

		testNsSizes = []testNamespaceSizes{size8, size16, size32}
	)

	for _, size := range testNsSizes {
		nidDataMap, sortedKeys := makeRandDataAndSortedKeys(size, minNumberOfNamespaces, maxNumberOfNamespaces, minElementsPerNamespace, maxElementsPerNamespace, emptyNamespaceProbability)
		t.Logf("Generated %v namespaces for size: %v ...", len(nidDataMap), size)
		hash := sha256.New()
		tree := nmt.New(hash, nmt.NamespaceIDSize(int(size)))

		// push data in order:
		for _, ns := range sortedKeys {
			leafDataList := nidDataMap[ns]
			for _, d := range leafDataList {
				err := tree.Push(d[:size], d[size:])
				if err != nil {
					t.Fatalf("error on Push(): %v", err)
				}
			}
		}

		treeRoot := tree.Root()
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
					t.Fatalf("returned data didn't math pushed data")
				}
				singleItemProof, err := tree.Prove(leafIdx)
				if err != nil {
					t.Fatalf("error on Prove(%v): %v", i, err)
				}
				if ok := singleItemProof.VerifyInclusion(hash, data[i][:size], data[i][size:], treeRoot); !ok {
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
}

func makeRandDataAndSortedKeys(size testNamespaceSizes, minNumOfNs, maxNumOfNs, minElemsPerNs, maxElemsPerNs int, emptyNsProb float64) (map[string][][]byte, []string) {
	nidDataMap := make(map[string][][]byte)
	f := makeFuzzer(size, minNumOfNs, maxNumOfNs, minElemsPerNs, maxElemsPerNs, emptyNsProb)
	f.Fuzz(&nidDataMap)
	keys := make([]string, len(nidDataMap))
	idx := 0
	for k := range nidDataMap {
		keys[idx] = k
		idx++
	}
	sort.Strings(keys)
	return nidDataMap, keys
}

type testNamespaceSizes int

const (
	size8  testNamespaceSizes = 8
	size16 testNamespaceSizes = 16
	size32 testNamespaceSizes = 32
)

func makeFuzzer(size testNamespaceSizes, minNumOfNs, maxNumOfNs, minElemsPerNs, maxElemsPerNs int, emptyNsProb float64) *fuzz.Fuzzer {
	switch size {
	case size8:
		var lastNs [size8]byte
		return fuzz.New().NilChance(0).NumElements(minNumOfNs, maxNumOfNs).Funcs(
			func(s *string, c fuzz.Continue) {
				// create a random namespace of size 8:
				c.Fuzz(&lastNs)
				*s = string(lastNs[:])
			},
			func(s *[][]byte, c fuzz.Continue) {
				var tmp [][]byte
				f := fuzz.New().NilChance(emptyNsProb).NumElements(minElemsPerNs, maxElemsPerNs)
				f.Fuzz(&tmp)
				*s = make([][]byte, len(tmp))
				for i, d := range tmp {
					d = append(d[:0], lastNs[:]...)
					(*s)[i] = d
				}
			})
	case size16:
		var lastNs [size16]byte
		return fuzz.New().NilChance(0).NumElements(minNumOfNs, maxNumOfNs).Funcs(
			func(s *string, c fuzz.Continue) {
				// create a random namespace of size 16:
				c.Fuzz(&lastNs)
				*s = string(lastNs[:])
			},
			func(s *[][]byte, c fuzz.Continue) {
				var tmp [][]byte
				f := fuzz.New().NilChance(emptyNsProb).NumElements(minElemsPerNs, maxElemsPerNs)
				f.Fuzz(&tmp)
				*s = make([][]byte, len(tmp))
				for i, d := range tmp {
					d = append(d[:0], lastNs[:]...)
					(*s)[i] = d
				}
			})
	case size32:
		var lastNs [size32]byte
		return fuzz.New().NilChance(0).NumElements(minNumOfNs, maxNumOfNs).Funcs(
			func(s *string, c fuzz.Continue) {
				// create a random namespace of size 32:
				c.Fuzz(&lastNs)
				*s = string(lastNs[:])
			},
			func(s *[][]byte, c fuzz.Continue) {
				var tmp [][]byte
				f := fuzz.New().NilChance(emptyNsProb).NumElements(minElemsPerNs, maxElemsPerNs)
				f.Fuzz(&tmp)
				*s = make([][]byte, len(tmp))
				for i, d := range tmp {
					d = append(d[:0], lastNs[:]...)
					(*s)[i] = d
				}
			})
	}
	panic("unsupported namespace size")
}
