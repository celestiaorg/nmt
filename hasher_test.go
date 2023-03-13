package nmt

import (
	"crypto"
	"crypto/sha256"
	"errors"
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

// defaultHasher uses sha256 as a base-hasher, 8 bytes for the namespace IDs and
// ignores the maximum possible namespace.
var defaultHasher = NewNmtHasher(sha256.New(), DefaultNamespaceIDLen, true)

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
			got, err := n.HashLeaf(tt.leaf)
			require.NoError(t, err)
			if !reflect.DeepEqual(got, tt.want) {
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
			got, err := n.HashNode(tt.children.l, tt.children.r)
			require.NoError(t, err)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HashNode() = %v, want %v", got, tt.want)
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

func TestHashNode_ChildrenNamespaceRange(t *testing.T) {
	type children struct {
		l []byte // namespace hash of the left child with the format of MinNs||MaxNs||h
		r []byte // namespace hash of the right child with the format of MinNs||MaxNs||h
	}

	tests := []struct {
		name     string
		nidLen   namespace.IDSize
		children children
		wantErr  bool // whether the test should error out
		errType  error
	}{
		{
			"left.maxNs>right.minNs", 2,
			children{[]byte{0, 0, 1, 1}, []byte{0, 0, 1, 1}},
			true, // this test case should emit error since in an ordered NMT, left.maxNs cannot be greater than right.minNs
			ErrUnorderedSiblings,
		},
		{
			"left.maxNs=right.minNs", 2,
			children{[]byte{0, 0, 1, 1}, []byte{1, 1, 2, 2}},
			false,
			nil,
		},
		{
			"left.maxNs<right.minNs", 2,
			children{[]byte{0, 0, 1, 1}, []byte{2, 2, 3, 3}},
			false,
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNmtHasher(sha256.New(), tt.nidLen, false)
			_, err := n.HashNode(tt.children.l, tt.children.r)
			assert.Equal(t, tt.wantErr, err != nil)
			if tt.wantErr {
				assert.True(t, errors.Is(err, tt.errType))
			}

		})
	}
}

func TestValidateSiblingsNamespaceOrder(t *testing.T) {
	type children struct {
		l []byte // namespace hash of the left child with the format of MinNs||MaxNs||h
		r []byte // namespace hash of the right child with the format of MinNs||MaxNs||h
	}

	tests := []struct {
		name     string
		nidLen   namespace.IDSize
		children children
		wantErr  bool
	}{
		{
			"left.maxNs>right.minNs", 2,
			children{[]byte{0, 0, 1, 1}, []byte{0, 0, 1, 1}},
			true,
		},
		{
			"left.maxNs=right.minNs", 2,
			children{[]byte{0, 0, 1, 1}, []byte{1, 1, 2, 2}},
			false,
		},
		{
			"left.maxNs<right.minNs", 2,
			children{[]byte{0, 0, 1, 1}, []byte{2, 2, 3, 3}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNmtHasher(sha256.New(), tt.nidLen, false)
			err := n.validateSiblingsNamespaceOrder(tt.children.l, tt.children.r)
			assert.Equal(t, tt.wantErr, err != nil)
		})
	}
}

func TestValidateNodeFormat(t *testing.T) {
	tests := []struct {
		name    string
		nIDLen  namespace.IDSize
		minNID  []byte
		maxNID  []byte
		hash    []byte
		wantErr bool
		errType error
	}{
		{ // valid node
			"valid node",
			2,
			[]byte{0, 0},
			[]byte{1, 1},
			[]byte{1, 2, 3, 4},
			false,
			nil,
		},
		{ // mismatched namespace size
			"invalid node: length",
			2,
			[]byte{0},
			[]byte{1},
			[]byte{0},
			true,
			ErrInvalidNodeLen,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNmtHasher(sha256.New(), tt.nIDLen, false)
			err := n.ValidateNodeFormat(append(append(tt.minNID, tt.maxNID...), tt.hash...))
			assert.Equal(t, tt.wantErr, err != nil)
			if tt.wantErr {
				assert.True(t, errors.Is(err, tt.errType))
			}
		})
	}
}

func TestIsNamespacedData(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		nIDLen  namespace.IDSize
		wantErr bool
	}{
		{
			"valid namespaced data",
			[]byte{0, 0},
			2,
			false,
		},
		{
			"non-namespaced data",
			[]byte{1},
			2,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNmtHasher(sha256.New(), tt.nIDLen, false)
			assert.Equal(t, tt.wantErr, n.ValidateLeaf(tt.data) != nil)
		})
	}
}

func TestHashLeafWithIsNamespacedData(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		nIDLen  namespace.IDSize
		wantErr bool
		errType error
	}{
		{
			"valid namespaced data",
			[]byte{0, 0},
			2,
			false,
			nil,
		},
		{
			"non-namespaced data",
			[]byte{1},
			2,
			true,
			ErrInvalidNodeLen,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNmtHasher(sha256.New(), tt.nIDLen, false)
			_, err := n.HashLeaf(tt.data)
			assert.Equal(t, tt.wantErr, err != nil)
			if tt.wantErr {
				assert.True(t, errors.Is(err, tt.errType))
			}
		})
	}
}

// TestHashNodeWithValidateNodes checks whether the HashNode errors out when invalid inputs are given.
// It also checks that the HashNode does not error out for valid inputs.
func TestHashNode_ErrorsCheck(t *testing.T) {
	type children struct {
		l []byte // namespace hash of the left child with the format of MinNs||MaxNs||h
		r []byte // namespace hash of the right child with the format of MinNs||MaxNs||h
	}

	tests := []struct {
		name     string
		nidLen   namespace.IDSize
		children children
		wantErr  bool
		errType  error
	}{
		{
			"left.maxNs<right.minNs", 2,
			children{[]byte{0, 0, 1, 1}, []byte{2, 2, 3, 3}},
			false,
			nil,
		},
		{
			"left.maxNs=right.minNs", 2,
			children{[]byte{0, 0, 1, 1}, []byte{1, 1, 2, 2}},
			false,
			nil,
		},
		{
			"left.maxNs>right.minNs", 2,
			children{[]byte{0, 0, 1, 1}, []byte{0, 0, 1, 1}},
			true,
			ErrUnorderedSiblings,
		},
		{
			"len(left)<NamespaceLen", 2,
			children{[]byte{0, 0, 1}, []byte{2, 2, 3, 3}},
			true,
			ErrInvalidNodeLen,
		},
		{
			"len(right)<NamespaceLen", 2,
			children{[]byte{0, 0, 1, 1}, []byte{2, 2, 3}},
			true,
			ErrInvalidNodeLen,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNmtHasher(sha256.New(), tt.nidLen, false)
			_, err := n.HashNode(tt.children.l, tt.children.r)
			assert.Equal(t, tt.wantErr, err != nil)
			if tt.wantErr {
				assert.True(t, errors.Is(err, tt.errType))
			}
		})
	}
}
