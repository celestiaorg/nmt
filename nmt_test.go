package nmt

import (
	"crypto"
	_ "crypto/sha256"
	"reflect"
	"testing"
)

func TestFromNamespaceAndData(t *testing.T) {
	tests := []struct {
		name      string
		namespace []byte
		data      []byte
		want      *NamespacePrefixedData
	}{
		0: {"simple case", []byte("namespace1"), []byte("data1"), &NamespacePrefixedData{10, append([]byte("namespace1"), []byte("data1")...)}},
		1: {"simpler case", []byte("1"), []byte("d"), &NamespacePrefixedData{1, append([]byte("1"), []byte("d")...)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FromNamespaceAndData(tt.namespace, tt.data); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromNamespaceAndData() = %v, want %v", got, tt.want)
			}
		})
	}
}

//nolint:errcheck
func Test_namespacedTreeHasher_HashLeaf(t *testing.T) {
	zeroNID := []byte{0}
	oneNID := []byte{1}
	longNID := []byte("namespace")

	defaultRawData := []byte("a blockchain is a chain of blocks")

	// Note: ensure we only hash in the raw data without the namespace prefixes
	emptyHash := sum(crypto.SHA256, []byte{LeafPrefix}, []byte{})
	defaultHash := sum(crypto.SHA256, []byte{LeafPrefix}, defaultRawData)

	oneNIDLeaf := append(oneNID, defaultRawData...)
	longNIDLeaf := append(longNID, defaultRawData...)

	tests := []struct {
		name  string
		nsLen int
		leaf  []byte
		want  []byte
	}{
		{"1 byte namespaced empty leaf", 1, zeroNID, append(append(zeroNID, zeroNID...), emptyHash...)},
		{"1 byte namespaced empty leaf", 1, oneNID, append(append(oneNID, oneNID...), emptyHash...)},
		{"1 byte namespaced leaf with data", 1, oneNIDLeaf, append(append(oneNID, oneNID...), defaultHash...)},
		{"namespaced empty leaf", 9, longNIDLeaf, append(append(longNID, longNID...), defaultHash...)},
		{"namespaced leaf with data", 9, longNID, append(append(longNID, longNID...), emptyHash...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := namespacedTreeHasher{
				Hash:         crypto.SHA256,
				NamespaceLen: tt.nsLen,
			}
			if got := n.HashLeaf(tt.leaf); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HashLeaf() = %v, want %v", got, tt.want)
			}
		})
	}
}

func sum(hash crypto.Hash, data ...[]byte) []byte {
	h := hash.New()
	for _, d := range data {
		h.Write(d)
	}

	return h.Sum(nil)
}

func Test_namespacedTreeHasher_HashNode(t *testing.T) {
	type fields struct {
		Hash         crypto.Hash
		NamespaceLen int
	}
	type args struct {
		l []byte
		r []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []byte
	}{
		// TODO: Add test cases!
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := namespacedTreeHasher{
				Hash:         tt.fields.Hash,
				NamespaceLen: tt.fields.NamespaceLen,
			}
			if got := n.HashNode(tt.args.l, tt.args.r); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HashNode() = %v, want %v", got, tt.want)
			}
		})
	}
}
