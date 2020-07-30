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
		//nolint:errcheck
		h.Write(d)
	}

	return h.Sum(nil)
}

func Test_namespacedTreeHasher_HashNode(t *testing.T) {
	sum(crypto.SHA256, []byte{NodePrefix}, []byte{0, 0, 0, 0}, []byte{1, 1, 1, 1})
	type children struct {
		l []byte
		r []byte
	}

	tests := []struct {
		name     string
		nidLen   int
		children children
		want     []byte
	}{
		{"leftmin<rightmin && leftmax<rightmax", 2,
			children{[]byte{0, 0, 0, 0}, []byte{1, 1, 1, 1}},
			append(
				[]byte{0, 0, 1, 1},
				sum(crypto.SHA256, []byte{NodePrefix}, []byte{0, 0, 0, 0}, []byte{1, 1, 1, 1})...,
			),
		},
		{"leftmin==rightmin && leftmax<rightmax", 2,
			children{[]byte{0, 0, 0, 0}, []byte{0, 0, 1, 1}},
			append(
				[]byte{0, 0, 1, 1},
				sum(crypto.SHA256, []byte{NodePrefix}, []byte{0, 0, 0, 0}, []byte{0, 0, 1, 1})...,
			),
		},
		{"leftmin==rightmin && leftmax>rightmax", 2,
			children{[]byte{0, 0, 1, 1}, []byte{0, 0, 0, 1}},
			append(
				[]byte{0, 0, 1, 1},
				sum(crypto.SHA256, []byte{NodePrefix}, []byte{0, 0, 1, 1}, []byte{0, 0, 0, 1})...,
			),
		},
		// XXX: can this happen in practice? or is this an invalid state?
		{"leftmin>rightmin && leftmax<rightmax", 2,
			children{[]byte{1, 1, 0, 0}, []byte{0, 0, 0, 1}},
			append(
				[]byte{0, 0, 1, 1},
				sum(crypto.SHA256, []byte{NodePrefix}, []byte{0, 0, 1, 1}, []byte{0, 0, 0, 1})...,
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := newNamespacedTreeHasher(tt.nidLen, crypto.SHA256)
			if got := n.HashNode(tt.children.l, tt.children.r); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HashNode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNamespacedMerkleTree_Push(t *testing.T) {
	tests := []struct {
		name    string
		data    NamespacePrefixedData
		wantErr bool
	}{
		{"1st push: always OK", *FromNamespaceAndData([]byte{0, 0, 0}, []byte("dummy data")), false},
		{"push with same namespace: OK", *FromNamespaceAndData([]byte{0, 0, 0}, []byte("dummy data")), false},
		{"push with greater namespace: OK", *FromNamespaceAndData([]byte{0, 0, 1}, []byte("dummy data")), false},
		{"push with smaller namespace: Err", *FromNamespaceAndData([]byte{0, 0, 0}, []byte("dummy data")), true},
		{"push with same namespace: Ok", *FromNamespaceAndData([]byte{0, 0, 1}, []byte("dummy data")), false},
		{"push with greater namespace: Ok", *FromNamespaceAndData([]byte{1, 0, 0}, []byte("dummy data")), false},
		{"push with smaller namespace: Err", *FromNamespaceAndData([]byte{0, 0, 1}, []byte("dummy data")), true},
		{"push with smaller namespace: Err", *FromNamespaceAndData([]byte{0, 0, 0}, []byte("dummy data")), true},
		{"push with smaller namespace: Err", *FromNamespaceAndData([]byte{0, 1, 0}, []byte("dummy data")), true},
		{"push with same as last namespace: OK", *FromNamespaceAndData([]byte{1, 0, 0}, []byte("dummy data")), false},
		{"push with greater as last namespace: OK", *FromNamespaceAndData([]byte{1, 1, 0}, []byte("dummy data")), false},
		// note this tests for another kind of error: ErrMismatchedNamespaceSize
		{"push with wrong namespace size: Err", *FromNamespaceAndData([]byte{1, 1, 0, 0}, []byte("dummy data")), true},
	}
	n := New(3, crypto.SHA256)
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

	tests := []struct {
		name       string
		nidLen     int
		pushedData []NamespacePrefixedData
		wantMinNs  NamespaceID
		wantMaxNs  NamespaceID
		wantRoot   []byte
	}{
		{"Empty", 3, nil, nil, nil, nil},
		{"One leaf", 3, []NamespacePrefixedData{*FromNamespaceAndData(zeroNs, leaf)}, zeroNs, zeroNs, leafHash},
		{"Two leafs", 3, []NamespacePrefixedData{*FromNamespaceAndData(zeroNs, leaf), *FromNamespaceAndData(zeroNs, leaf)}, zeroNs, zeroNs, twoZeroLeafsRoot},
		{"Two leafs diff namespaces", 3, []NamespacePrefixedData{*FromNamespaceAndData(zeroNs, leaf), *FromNamespaceAndData(onesNS, leaf)}, zeroNs, onesNS, diffNSLeafsRoot},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := New(tt.nidLen, crypto.SHA256)
			for _, d := range tt.pushedData {
				if err := n.Push(d); err != nil {
					t.Errorf("Push() error = %v, expected no error", err)
				}
			}
			gotMinNs, gotMaxNs, gotRoot := n.Root()
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
