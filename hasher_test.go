package nmt

import (
	"bytes"
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
	// create a dummy hash to use as the digest of the left and right child
	randHash := createByteSlice(crypto.SHA256.Size(), 0x01)
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
			children{
				concat([]byte{0, 0, 0, 0}, randHash),
				concat([]byte{1, 1, 1, 1}, randHash),
			},
			concat([]byte{0, 0, 1, 1}, // minNID||maxNID
				sum(crypto.SHA256, []byte{NodePrefix}, // Hash(NodePrefix||left||right)
					concat([]byte{0, 0, 0, 0}, randHash),
					concat([]byte{1, 1, 1, 1}, randHash))),
		},
		{
			"leftmin==rightmin && leftmax<rightmax", 2,
			children{
				concat([]byte{0, 0, 0, 0}, randHash),
				concat([]byte{0, 0, 1, 1}, randHash),
			},
			concat([]byte{0, 0, 1, 1}, // minNID||maxNID
				sum(crypto.SHA256, []byte{NodePrefix}, // Hash(NodePrefix||left||right)
					concat([]byte{0, 0, 0, 0}, randHash),
					concat([]byte{0, 0, 1, 1}, randHash))),
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

// concat concatenates the given byte slices.
func concat(data ...[]byte) []byte {
	var result []byte
	for _, d := range data {
		result = append(result, d...)
	}

	return result
}

// createByteSlice returns a byte slice of length n with all bytes set to b.
func createByteSlice(n int, b byte) []byte {
	return bytes.Repeat([]byte{b}, n)
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

// TestHashNode verifies the HashNode function for scenarios where it is expected to produce errors, as well as those where it is not.
func TestHashNode_Error(t *testing.T) {
	// create a dummy hash to use as the digest of the left and right child
	randHash := createByteSlice(sha256.Size, 0x01)
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
			"unordered siblings: left.maxNs>right.minNs", 2,
			children{
				concat([]byte{0, 0, 1, 1}, randHash),
				concat([]byte{0, 0, 1, 1}, randHash),
			},
			true, // this test case should emit an error since in an ordered NMT, left.maxNs cannot be greater than right.minNs
			ErrUnorderedSiblings,
		},
		{
			"ordered siblings: left.maxNs=right.minNs", 2,
			children{
				concat([]byte{0, 0, 1, 1}, randHash),
				concat([]byte{1, 1, 2, 2}, randHash),
			},
			false,
			nil,
		},
		{
			"ordered siblings: left.maxNs<right.minNs", 2,
			children{
				concat([]byte{0, 0, 1, 1}, randHash),
				concat([]byte{2, 2, 3, 3}, randHash),
			},
			false,
			nil,
		},
		{
			"invalid left sibling format: left.minNs>left.maxNs", 2,
			children{
				concat([]byte{2, 2, 0, 0}, randHash),
				concat([]byte{1, 1, 4, 4}, randHash),
			},
			true,
			ErrInvalidNodeNamespaceOrder,
		},
		{
			"invalid right sibling format: right.minNs>right.maxNs", 2,
			children{
				concat([]byte{0, 0, 1, 1}, randHash),
				concat([]byte{4, 4, 1, 1}, randHash),
			},
			true,
			ErrInvalidNodeNamespaceOrder,
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

func TestValidateNodeFormat(t *testing.T) {
	hashValue := createByteSlice(sha256.Size, 0x01)
	minNID := createByteSlice(2, 0x00)
	maxNID := createByteSlice(2, 0x01)
	tests := []struct {
		name    string
		nIDLen  namespace.IDSize
		minNID  []byte
		maxNID  []byte
		hash    []byte
		wantErr bool
		errType error
	}{
		{
			"valid node",
			2,
			minNID,
			maxNID,
			hashValue,
			false,
			nil,
		},
		{
			"invalid node: length < 2 * namespace size",
			2,
			minNID,
			[]byte{},
			[]byte{},
			true,
			ErrInvalidNodeLen,
		},
		{
			"invalid node: length < 2 * namespace Size + hash size",
			2,
			minNID,
			maxNID,
			[]byte{},
			true,
			ErrInvalidNodeLen,
		},
		{
			"invalid node: length > 2 * namespace size + hash size",
			2,
			minNID,
			maxNID,
			concat(hashValue, []byte{1}),
			true,
			ErrInvalidNodeLen,
		},
		{
			"invalid node: minNS > maxNs",
			2,
			[]byte{3, 3},
			[]byte{1, 1},
			concat(hashValue),
			true,
			ErrInvalidNodeNamespaceOrder,
		},
		{
			"valid node: minNs = maxNs",
			2,
			minNID,
			minNID,
			concat(hashValue),
			false,
			nil,
		},
		{
			"valid node: minNs < maxNs",
			2,
			minNID,
			maxNID,
			concat(hashValue),
			false,
			nil,
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

func TestValidateLeaf(t *testing.T) {
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

// TestValidateLeafWithHash tests the HashLeaf does not error out for the leaves that are validated by ValidateLeaf.
func TestValidateLeafWithHash(t *testing.T) {
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
			validationRes := n.ValidateLeaf(tt.data)
			assert.Equal(t, tt.wantErr, validationRes != nil)
			_, err := n.HashLeaf(tt.data)
			assert.Equal(t, validationRes != nil, err != nil)
		})
	}
}

func TestHashLeafWithIsNamespacedData(t *testing.T) {
	tests := []struct {
		name    string
		leaf    []byte
		nIDLen  namespace.IDSize
		wantErr bool
		errType error
	}{
		{
			"valid namespaced leaf",
			[]byte{0, 0},
			2,
			false,
			nil,
		},
		{
			"non-namespaced leaf",
			[]byte{1},
			2,
			true,
			ErrInvalidLeafLen,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNmtHasher(sha256.New(), tt.nIDLen, false)
			_, err := n.HashLeaf(tt.leaf)
			assert.Equal(t, tt.wantErr, err != nil)
			if tt.wantErr {
				assert.True(t, errors.Is(err, tt.errType))
			}
		})
	}
}

// TestHashNode_ErrorsCheck checks that the HashNode emits error only on invalid inputs. It also checks whether the returned error types are correct.
func TestHashNode_ErrorsCheck(t *testing.T) {
	// create a dummy hash to use as the digest of the left and right child
	randHash := createByteSlice(sha256.Size, 0x01)
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
			children{
				concat([]byte{0, 0, 1, 1}, randHash),
				concat([]byte{2, 2, 3, 3}, randHash),
			},
			false,
			nil,
		},
		{
			"left.maxNs=right.minNs", 2,
			children{
				concat([]byte{0, 0, 1, 1}, randHash),
				concat([]byte{1, 1, 2, 2}, randHash),
			},
			false,
			nil,
		},
		{
			"left.maxNs>right.minNs", 2,
			children{
				concat([]byte{0, 0, 1, 1}, randHash),
				concat([]byte{0, 0, 1, 1}, randHash),
			},
			true,
			ErrUnorderedSiblings,
		},
		{
			"len(left)<hasher.Size", 2,
			children{
				[]byte{0, 0, 1},
				concat([]byte{2, 2, 3, 3}, randHash),
			},
			true,
			ErrInvalidNodeLen,
		},
		{
			"len(right)<hasher.Size", 2,
			children{
				concat([]byte{0, 0, 1, 1}, randHash),
				[]byte{2, 2, 3},
			},
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

// TestWrite_Err checks that the Write method emits error on invalid inputs.
func TestWrite_Err(t *testing.T) {
	hash := sha256.New()
	hash.Write([]byte("random data"))
	randData := hash.Sum(nil)

	tests := []struct {
		name    string
		hasher  *NmtHasher
		data    []byte
		wantErr bool
		errType error
	}{
		{
			"invalid leaf",
			NewNmtHasher(sha256.New(), 2, false),
			[]byte{0},
			true,
			ErrInvalidLeafLen,
		},
		{
			"invalid node: left.max > right.min",
			NewNmtHasher(sha256.New(), 2, false),
			append(append(append([]byte{0, 0, 2, 2}, randData...), []byte{1, 1, 3, 3}...), randData...),
			true,
			ErrUnorderedSiblings,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.hasher.Write(tt.data)
			assert.Equal(t, tt.wantErr, err != nil)
			if tt.wantErr {
				assert.True(t, errors.Is(err, tt.errType))
			}
		})
	}
}

// TestSum_Err checks that the Sum method emits error on invalid inputs and when the hasher is not in the correct state.
func TestSum_Err(t *testing.T) {
	hash := sha256.New()
	hash.Write([]byte("random data"))
	randData := hash.Sum(nil)

	tests := []struct {
		name         string
		hasher       *NmtHasher
		data         []byte
		nodeType     byte
		wantWriteErr bool
	}{
		{
			"invalid leaf: not namespaced",
			NewNmtHasher(sha256.New(), 2, false),
			[]byte{0},
			LeafPrefix,
			true,
		},
		{
			"invalid node: left.max > right.min",
			NewNmtHasher(sha256.New(), 2, false),
			append(append(append([]byte{0, 0, 2, 2}, randData...), []byte{1, 1, 3, 3}...), randData...),
			NodePrefix,
			true,
		},
	}
	for _, tt := range tests {
		// Write -> Sum should never panic
		_, err := tt.hasher.Write(tt.data)
		require.Equal(t, tt.wantWriteErr, err != nil)
		if err == nil {
			require.NotPanics(t, func() {
				tt.hasher.Sum(nil)
			})
		}
		// Sum without a preceding Write for a wrong data should panic
		if err != nil {
			tt.hasher.Reset()
			tt.hasher.data = tt.data   // by-pass the Write method
			tt.hasher.tp = tt.nodeType // by-pass the Write method
			require.Panics(t, func() {
				_ = tt.hasher.Sum(nil)
			})
		}
	}
}

// TestValidateNodes checks that the ValidateNodes method only emits error on invalid inputs. It also checks whether the returned error types are correct.
func TestValidateNodes(t *testing.T) {
	// create a dummy hash to use as the digest of the left and right child
	randHash := createByteSlice(sha256.Size, 0x01)
	tests := []struct {
		name    string
		nIDLen  namespace.IDSize
		left    []byte
		right   []byte
		wantErr bool
		errType error
	}{
		{
			"left.maxNs<right.minNs",
			2,
			concat([]byte{0, 0, 1, 1}, randHash),
			concat([]byte{2, 2, 3, 3}, randHash),
			false,
			nil,
		},
		{
			"left.maxNs=right.minNs",
			2,
			concat([]byte{0, 0, 1, 1}, randHash),
			concat([]byte{1, 1, 2, 2}, randHash),
			false,
			nil,
		},
		{
			"left.maxNs>right.minNs",
			2,
			concat([]byte{0, 0, 1, 1}, randHash),
			concat([]byte{0, 0, 1, 1}, randHash),
			true,
			ErrUnorderedSiblings,
		},
		{
			"len(left)<NamespaceLen",
			2,
			[]byte{0, 0, 1},
			concat([]byte{2, 2, 3, 3}, randHash),
			true,
			ErrInvalidNodeLen,
		},
		{
			"len(right)<NamespaceLen", 2,
			concat([]byte{0, 0, 1, 1}, randHash),
			[]byte{2, 2, 3},
			true,
			ErrInvalidNodeLen,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNmtHasher(sha256.New(), tt.nIDLen, false)
			err := n.ValidateNodes(tt.left, tt.right)
			assert.Equal(t, tt.wantErr, err != nil)
			if tt.wantErr {
				assert.True(t, errors.Is(err, tt.errType))
			}
		})
	}
}

// Test_MustHashLeaf_panic checks that the MustHashLeaf method panics only on invalid inputs.
func Test_MustHashLeaf_Panic(t *testing.T) {
	hasher := NewNmtHasher(sha256.New(), 2, false)
	tests := []struct {
		name      string
		leaf      []byte
		wantPanic bool
	}{
		{"valid leaf length", []byte{0, 0}, false},
		{"invalid leaf length", []byte{0}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				assert.Panics(t, func() {
					hasher.MustHashLeaf(tt.leaf)
				})
			} else {
				assert.NotPanics(t, func() {
					hasher.MustHashLeaf(tt.leaf)
				})
			}
		})
	}
}

func TestMax(t *testing.T) {
	tt := []struct {
		name     string
		ns       []byte
		ns2      []byte
		expected []byte
	}{
		{
			"First argument is larger",
			[]byte{1, 2, 3},
			[]byte{1, 2},
			[]byte{1, 2, 3},
		},
		{
			"Second argument is larger",
			[]byte{1, 2},
			[]byte{1, 2, 3},
			[]byte{1, 2, 3},
		},
		{
			"Arguments are equal",
			[]byte{1, 2, 3},
			[]byte{1, 2, 3},
			[]byte{1, 2, 3},
		},
	}

	for _, ts := range tt {
		t.Run(ts.name, func(t *testing.T) {
			maxResult := max(ts.ns, ts.ns2)
			assert.Equal(t, ts.expected, maxResult)
		})
	}
}

func TestMin(t *testing.T) {
	tt := []struct {
		name     string
		ns       []byte
		ns2      []byte
		expected []byte
	}{
		{
			"First argument is smaller",
			[]byte{1, 2},
			[]byte{1, 2, 3},
			[]byte{1, 2},
		},
		{
			"Second argument is smaller",
			[]byte{1, 2, 3},
			[]byte{1, 2},
			[]byte{1, 2},
		},
		{
			"Arguments are equal",
			[]byte{1, 2, 3},
			[]byte{1, 2, 3},
			[]byte{1, 2, 3},
		},
	}

	for _, ts := range tt {
		t.Run(ts.name, func(t *testing.T) {
			minResult := min(ts.ns, ts.ns2)
			assert.Equal(t, ts.expected, minResult)
		})
	}
}

// TestComputeNsRange tests the ComputeRange function.
func TestComputeNsRange(t *testing.T) {
	nIDSize := 1
	precomputedMaxNs := bytes.Repeat([]byte{0xFF}, nIDSize)

	testCases := []struct {
		leftMinNs, leftMaxNs, rightMinNs, rightMaxNs, expectedMinNs, expectedMaxNs []byte
		ignoreMaxNs                                                                bool
	}{
		{
			ignoreMaxNs:   true,
			leftMinNs:     precomputedMaxNs,
			leftMaxNs:     precomputedMaxNs,
			rightMinNs:    precomputedMaxNs,
			rightMaxNs:    precomputedMaxNs,
			expectedMinNs: precomputedMaxNs,
			expectedMaxNs: precomputedMaxNs,
		},
		{
			ignoreMaxNs:   true,
			leftMinNs:     []byte{0x00},
			leftMaxNs:     precomputedMaxNs,
			rightMinNs:    precomputedMaxNs,
			rightMaxNs:    precomputedMaxNs,
			expectedMinNs: []byte{0x00},
			expectedMaxNs: precomputedMaxNs,
		},
		{
			ignoreMaxNs:   true,
			leftMinNs:     []byte{0x00},
			leftMaxNs:     []byte{0x01},
			rightMinNs:    precomputedMaxNs,
			rightMaxNs:    precomputedMaxNs,
			expectedMinNs: []byte{0x00},
			expectedMaxNs: []byte{0x01},
		},
		{
			ignoreMaxNs:   true,
			leftMinNs:     []byte{0x00},
			leftMaxNs:     []byte{0x01},
			rightMinNs:    []byte{0x02},
			rightMaxNs:    precomputedMaxNs,
			expectedMinNs: []byte{0x00},
			expectedMaxNs: precomputedMaxNs,
		},
		{
			ignoreMaxNs:   true,
			leftMinNs:     []byte{0x00},
			leftMaxNs:     []byte{0x01},
			rightMinNs:    []byte{0x02},
			rightMaxNs:    []byte{0x03},
			expectedMinNs: []byte{0x00},
			expectedMaxNs: []byte{0x03},
		},
		{
			ignoreMaxNs:   false,
			leftMinNs:     precomputedMaxNs,
			leftMaxNs:     precomputedMaxNs,
			rightMinNs:    precomputedMaxNs,
			rightMaxNs:    precomputedMaxNs,
			expectedMinNs: precomputedMaxNs,
			expectedMaxNs: precomputedMaxNs,
		},
		{
			ignoreMaxNs:   false,
			leftMinNs:     []byte{0x00},
			leftMaxNs:     precomputedMaxNs,
			rightMinNs:    precomputedMaxNs,
			rightMaxNs:    precomputedMaxNs,
			expectedMinNs: []byte{0x00},
			expectedMaxNs: precomputedMaxNs,
		},
		{
			ignoreMaxNs:   false,
			leftMinNs:     []byte{0x00},
			leftMaxNs:     []byte{0x01},
			rightMinNs:    precomputedMaxNs,
			rightMaxNs:    precomputedMaxNs,
			expectedMinNs: []byte{0x00},
			expectedMaxNs: precomputedMaxNs,
		},
		{
			ignoreMaxNs:   false,
			leftMinNs:     []byte{0x00},
			leftMaxNs:     []byte{0x01},
			rightMinNs:    []byte{0x02},
			rightMaxNs:    precomputedMaxNs,
			expectedMinNs: []byte{0x00},
			expectedMaxNs: precomputedMaxNs,
		},
		{
			ignoreMaxNs:   false,
			leftMinNs:     []byte{0x00},
			leftMaxNs:     []byte{0x01},
			rightMinNs:    []byte{0x02},
			rightMaxNs:    []byte{0x03},
			expectedMinNs: []byte{0x00},
			expectedMaxNs: []byte{0x03},
		},
	}

	for _, tc := range testCases {
		minNs, maxNs := computeNsRange(tc.leftMinNs, tc.leftMaxNs, tc.rightMinNs, tc.rightMaxNs, tc.ignoreMaxNs, precomputedMaxNs)
		assert.True(t, bytes.Equal(tc.expectedMinNs, minNs))
		assert.True(t, bytes.Equal(tc.expectedMaxNs, maxNs))
	}
}

// TestEmptyRoot ensures that the empty root is always the same, under the same configuration, regardless of the state of the Hasher.
func TestEmptyRoot(t *testing.T) {
	nIDSzie := 1
	ignoreMaxNS := true

	hasher := NewNmtHasher(sha256.New(), namespace.IDSize(nIDSzie), ignoreMaxNS)
	expectedEmptyRoot := hasher.EmptyRoot()

	// perform some operation with the hasher
	_, err := hasher.HashNode(createByteSlice(hasher.Size(), 1), createByteSlice(hasher.Size(), 1))
	assert.NoError(t, err)
	gotEmptyRoot := hasher.EmptyRoot()

	// the empty root should be the same before and after the operation
	assert.True(t, bytes.Equal(gotEmptyRoot, expectedEmptyRoot))
}
