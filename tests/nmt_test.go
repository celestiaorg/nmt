package simple

import (
	"bytes"
	"crypto/sha256"
	"math/rand"
	"reflect"
	"sort"
	"testing"

	"github.com/lazyledger/nmt"
	"github.com/lazyledger/nmt/namespace"
)

func TestNMTreeImplementationsEquivalent(t *testing.T) {
	var (
		hash      = sha256.New()
		nidSize   = 8
		minNID    = []byte{0, 0, 0, 0, 0, 0, 0, 0}
		secondNID = []byte{0, 0, 0, 0, 0, 0, 0, 1}
		thirdNID  = []byte{0, 0, 0, 0, 0, 0, 0, 2}
	)
	data := generateRandNamespacedRawData(1024, nidSize, 256)
	prefixedData := make([]namespace.Data, len(data))
	for i, d := range data {
		prefixedData[i] = namespace.PrefixedData8(d)
	}
	tests := []struct {
		name       string
		pushedData []namespace.Data
	}{
		{"4 leaves, none maxNID (ignored)",
			[]namespace.Data{
				namespace.PrefixedData8(append(minNID, []byte("leaf_1")...)),
				namespace.PrefixedData8(append(minNID, []byte("leaf_2")...)),
				namespace.PrefixedData8(append(secondNID, []byte("leaf_3")...)),
				namespace.PrefixedData8(append(thirdNID, []byte("leaf_4")...)),
			},
		},
		{"random",
			prefixedData,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n1 := NewNMTree(namespace.IDSize(nidSize))
			n2 := nmt.New(hash, nmt.NamespaceIDSize(nidSize))
			for _, d := range tt.pushedData {
				if err := n1.Push(d.NamespaceID(), d.Data()); err != nil {
					t.Errorf("Push() error = %v, expected no error", err)
				}
				if err := n2.Push(d); err != nil {
					t.Errorf("Push() error = %v, expected no error", err)
				}
			}
			if got, want := n1.Root(), n2.Root(); !reflect.DeepEqual(got, want.Bytes()) {
				t.Errorf("Root() = %v, want %v", got, want.Bytes())
			}
		})
	}
}

func BenchmarkCompareImpls(b *testing.B) {
	b.ReportAllocs()
	var (
		total    = 256
		leafSize = 256
		nidSize  = 8
	)

	data := generateRandNamespacedRawData(total, nidSize, leafSize)

	b.ResetTimer()
	b.Run("simple", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			n := NewNMTree(namespace.IDSize(nidSize))
			for j := 0; j < total; j++ {
				if err := n.Push(data[j][:nidSize], data[j][nidSize:]); err != nil {
					b.Errorf("err: %v", err)
				}
			}
			_ = n.Root()
		}
	})
	var r namespace.IntervalDigest
	b.Run("neboulous-based", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			n := nmt.New(sha256.New())
			for j := 0; j < total; j++ {
				if err := n.Push(namespace.PrefixedData8(data[j])); err != nil {
					b.Errorf("err: %v", err)
				}
			}
			r = n.Root()
			_ = r.Bytes()
		}
	})
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
