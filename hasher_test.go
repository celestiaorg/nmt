package nmt

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/nmt/namespace"
)

const (
	hashSize  = sha256.Size + (2 * DefaultNamespaceIDLen)
	leafSize  = DefaultNamespaceIDLen + 512
	innerSize = 2 * hashSize
)

func Test_namespacedTreeHasher_HashLeaf(t *testing.T) {
	zeroNID := []byte{0}
	oneNID := []byte{1}
	longNID := []byte("namespace")

	defaultRawData := []byte("a blockchain is a chain of blocks")

	// Note: ensure we only hash in the raw data without the namespace prefixes
	emptyHashZeroNID := sum(crypto.SHA256, []byte{LeafPrefix}, zeroNID, []byte{})
	emptyHashOneNID := sum(crypto.SHA256, []byte{LeafPrefix}, oneNID, []byte{})
	defaultHashOneNID := sum(crypto.SHA256, []byte{LeafPrefix}, oneNID, defaultRawData)
	defaultHashLongNID := sum(crypto.SHA256, []byte{LeafPrefix}, longNID, defaultRawData)

	oneNIDLeaf := append(oneNID, defaultRawData...)
	longNIDLeaf := append(longNID, defaultRawData...)

	tests := []struct {
		name  string
		nsLen namespace.IDSize
		leaf  []byte
		want  []byte
	}{
		{"1 byte namespaced empty leaf", 1, zeroNID, append(append(zeroNID, zeroNID...), emptyHashZeroNID...)},
		{"1 byte namespaced empty leaf", 1, oneNID, append(append(oneNID, oneNID...), emptyHashOneNID...)},
		{"1 byte namespaced leaf with data", 1, oneNIDLeaf, append(append(oneNID, oneNID...), defaultHashOneNID...)},
		{"namespaced leaf with data", 9, longNIDLeaf, append(append(longNID, longNID...), defaultHashLongNID...)},
		{"namespaced empty leaf", 9, longNID, append(append(longNID, longNID...), sum(crypto.SHA256, []byte{LeafPrefix}, longNID, []byte{})...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNmtHasher(sha256.New(), tt.nsLen, false)
			if got := n.HashLeaf(tt.leaf); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HashLeaf() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_namespacedTreeHasher_HashNode(t *testing.T) {
	sum(crypto.SHA256, []byte{NodePrefix}, []byte{0, 0, 0, 0}, []byte{1, 1, 1, 1})
	type children struct {
		l []byte
		r []byte
	}

	tests := []struct {
		name     string
		nidLen   namespace.IDSize
		children children
		want     []byte
	}{
		{
			"leftmin<rightmin && leftmax<rightmax", 2,
			children{[]byte{0, 0, 0, 0}, []byte{1, 1, 1, 1}},
			append(
				[]byte{0, 0, 1, 1},
				sum(crypto.SHA256, []byte{NodePrefix}, []byte{0, 0, 0, 0}, []byte{1, 1, 1, 1})...,
			),
		},
		{
			"leftmin==rightmin && leftmax<rightmax", 2,
			children{[]byte{0, 0, 0, 0}, []byte{0, 0, 1, 1}},
			append(
				[]byte{0, 0, 1, 1},
				sum(crypto.SHA256, []byte{NodePrefix}, []byte{0, 0, 0, 0}, []byte{0, 0, 1, 1})...,
			),
		},
		{
			"leftmin==rightmin && leftmax>rightmax", 2,
			children{[]byte{0, 0, 1, 1}, []byte{0, 0, 0, 1}},
			append(
				[]byte{0, 0, 1, 1},
				sum(crypto.SHA256, []byte{NodePrefix}, []byte{0, 0, 1, 1}, []byte{0, 0, 0, 1})...,
			),
		},
		// XXX: can this happen in practice? or is this an invalid state?
		{
			"leftmin>rightmin && leftmax<rightmax", 2,
			children{[]byte{1, 1, 0, 0}, []byte{0, 0, 0, 1}},
			append(
				[]byte{0, 0, 0, 1},
				sum(crypto.SHA256, []byte{NodePrefix}, []byte{1, 1, 0, 0}, []byte{0, 0, 0, 1})...,
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNmtHasher(sha256.New(), tt.nidLen, false)
			if got := n.HashNode(tt.children.l, tt.children.r); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HashNode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSha256Namespace16FlaggedLeaf(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		wantPanic bool
		wantLen   int
	}{
		{"input too short: panic", []byte("smaller"), true, 0},
		{"input 16 byte: Ok", []byte("16 byte string  "), false, 64},
		{"input greater 16 byte: Ok", []byte("20 byte string      "), false, 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				shouldPanic(t, func() {
					Sha256Namespace16FlaggedLeaf(tt.data)
				})
			} else if got := Sha256Namespace16FlaggedLeaf(tt.data); len(got) != tt.wantLen {
				t.Errorf("len(Sha256Namespace16FlaggedLeaf()) = %v, want %v", got, tt.wantLen)
			}
		})
	}
}

func TestSha256Namespace16FlaggedInner(t *testing.T) {
	nilHash := sha256.Sum256(nil)
	nid1 := bytes.Repeat([]byte{1}, 16)
	nid2 := bytes.Repeat([]byte{2}, 16)
	tests := []struct {
		name      string
		data      []byte
		wantPanic bool
		wantLen   int
	}{
		{"input smaller than 48 bytes: panic", []byte("smaller48"), true, 0},
		{"input still too small: panic", append(append(nid1, nid2...), []byte("data")...), true, 0},
		{"valid input: ok", append(append(append(nid1, nilHash[:]...), nid2...), nilHash[:]...), false, 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				shouldPanic(t, func() {
					Sha256Namespace16FlaggedInner(tt.data)
				})
			} else if got := Sha256Namespace16FlaggedInner(tt.data); len(got) != tt.wantLen {
				t.Errorf("len(Sha256Namespace8FlaggedLeaf()) = %v, want %v", got, tt.wantLen)
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

func TestNamespaceHasherWrite(t *testing.T) {
	tt := []struct {
		name         string
		expectedSize int
		writtenSize  int
	}{
		{
			"Leaf",
			leafSize,
			leafSize,
		},
		{
			"Inner",
			innerSize,
			innerSize,
		},
	}

	for _, ts := range tt {
		t.Run("Success"+ts.name, func(t *testing.T) {
			h := defaultHasher
			h.Reset()
			n, err := h.Write(make([]byte, ts.writtenSize))
			assert.NoError(t, err)
			assert.Equal(t, ts.expectedSize, n)
			assert.Equal(t, ts.expectedSize, len(h.data))
		})
	}

	t.Run("ErrorSecondWrite", func(t *testing.T) {
		h := defaultHasher
		h.Reset()
		n, err := h.Write(make([]byte, leafSize))
		assert.NoError(t, err)
		assert.Equal(t, leafSize, n)

		require.Panics(t, func() {
			_, _ = h.Write(make([]byte, leafSize))
		})
	})
}

func TestNamespaceHasherSum(t *testing.T) {
	tt := []struct {
		name         string
		expectedSize int
		writtenSize  int
	}{
		{
			"Leaf",
			hashSize,
			leafSize,
		},
		{
			"Inner",
			hashSize,
			innerSize,
		},
	}

	for _, ts := range tt {
		t.Run("Success"+ts.name, func(t *testing.T) {
			h := defaultHasher
			h.Reset()
			_, _ = h.Write(make([]byte, ts.writtenSize))
			sum := h.Sum(nil)
			assert.Equal(t, len(sum), ts.expectedSize)
		})
	}
}
