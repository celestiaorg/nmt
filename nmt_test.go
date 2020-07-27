package nmt

import (
	"crypto"
	"crypto/sha256"
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
	const nsLen = 8
	h := sha256.New()
	h.Write([]byte{LeafPrefix})
	h.Write([]byte{})
	emptyHash := h.Sum(nil)
	tests := []struct {
		name string
		leaf []byte
		want []byte
	}{
		{"namespaced empty leaf", []byte("namespac"), append(append([]byte("namespac"), []byte("namespac")...), emptyHash...)},
		// TODO: Add more test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := namespacedTreeHasher{
				Hash:         crypto.SHA256,
				NamespaceLen: nsLen,
			}
			if got := n.HashLeaf(tt.leaf); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HashLeaf() = %v, want %v", got, tt.want)
			}
		})
	}
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
