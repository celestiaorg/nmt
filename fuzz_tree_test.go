package nmt_test

import (
	"bytes"
	"crypto/sha256"
	"math/bits"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/nmt"
	"github.com/celestiaorg/nmt/namespace"
)

// FuzzHasher calls the NmtHasher methods with arbitrary inputs and namespace
// sizes. Invalid input must return an error, never panic. Valid input must
// produce the namespaced hash format of the spec, Write+Sum must agree with
// HashLeaf and HashNode, and the root of a two-leaf tree must equal HashNode
// of the two leaf hashes.
func FuzzHasher(f *testing.F) {
	f.Add(uint8(8), false, []byte{}, []byte{})
	f.Add(uint8(1), true, []byte{1, 2}, []byte{3, 4})
	f.Add(uint8(0), false, []byte("leaf"), []byte("leaf"))
	f.Add(uint8(29), true, bytes.Repeat([]byte{0xFF}, 100), bytes.Repeat([]byte{0xFF}, 100))
	nth := nmt.NewNmtHasher(sha256.New(), 1, true)
	left, right := nth.MustHashLeaf([]byte{1, 1}), nth.MustHashLeaf([]byte{0xFF, 2})
	f.Add(uint8(1), true, left, right)
	f.Add(uint8(1), true, append(bytes.Clone(left), right...), right)
	f.Fuzz(func(t *testing.T, nsSize uint8, ignoreMax bool, a, b []byte) {
		ns := int(nsSize)
		nth := nmt.NewNmtHasher(sha256.New(), namespace.IDSize(nsSize), ignoreMax)
		nodeSize := nth.Size()
		require.Equal(t, sha256.Size+2*ns, nodeSize)
		require.Len(t, nth.EmptyRoot(), nodeSize)

		for _, leaf := range [][]byte{a, b} {
			hash, err := nth.HashLeaf(leaf)
			require.Equal(t, len(leaf) < ns, err != nil)
			require.Equal(t, err != nil, nth.ValidateLeaf(leaf) != nil)
			if err != nil {
				continue
			}
			digest := sha256.Sum256(append([]byte{nmt.LeafPrefix}, leaf...))
			want := append(append(bytes.Clone(leaf[:ns]), leaf[:ns]...), digest[:]...)
			require.Equal(t, want, hash)
		}

		for _, node := range [][]byte{a, b} {
			err := nth.ValidateNodeFormat(node)
			valid := len(node) == nodeSize && bytes.Compare(node[ns:2*ns], node[:ns]) >= 0
			require.Equal(t, valid, err == nil, "ValidateNodeFormat(%x) = %v", node, err)
		}

		hash, err := nth.HashNode(a, b)
		require.Equal(t, nth.ValidateNodes(a, b) != nil, err != nil)
		if err == nil {
			digest := sha256.Sum256(append(append([]byte{nmt.NodePrefix}, a...), b...))
			maxNs := b[ns : 2*ns]
			if ignoreMax && isMaxNamespace(b[:ns]) {
				maxNs = a[ns : 2*ns]
			}
			want := append(append(bytes.Clone(a[:ns]), maxNs...), digest[:]...)
			require.Equal(t, want, hash)
			// the left max must not exceed the right min
			require.LessOrEqual(t, bytes.Compare(a[ns:2*ns], b[:ns]), 0)
		}

		// hash.Hash interface: a single Write followed by Sum
		for _, data := range [][]byte{a, b, append(bytes.Clone(a), b...)} {
			h := nmt.NewNmtHasher(sha256.New(), namespace.IDSize(nsSize), ignoreMax)
			n, err := h.Write(data)
			if len(data) == 2*nodeSize {
				require.Equal(t, h.ValidateNodes(data[:nodeSize], data[nodeSize:]) != nil, err != nil)
			} else {
				require.Equal(t, h.ValidateLeaf(data) != nil, err != nil)
			}
			if err != nil {
				continue
			}
			require.Equal(t, len(data), n)
			var want []byte
			if len(data) == 2*nodeSize {
				want, err = nth.HashNode(data[:nodeSize], data[nodeSize:])
			} else {
				want, err = nth.HashLeaf(data)
			}
			require.NoError(t, err)
			require.Equal(t, want, h.Sum(nil))
		}

		// differential: tree root of two leaves vs HashNode of the leaf hashes
		if len(a) >= ns && len(b) >= ns && bytes.Compare(a[:ns], b[:ns]) <= 0 {
			tree := nmt.New(sha256.New(), nmt.NamespaceIDSize(ns), nmt.IgnoreMaxNamespace(ignoreMax))
			require.NoError(t, tree.Push(a))
			root, err := tree.Root()
			require.NoError(t, err)
			require.Equal(t, nth.MustHashLeaf(a), root)
			require.NoError(t, tree.Push(b))
			root, err = tree.Root()
			require.NoError(t, err)
			want, err := nth.HashNode(nth.MustHashLeaf(a), nth.MustHashLeaf(b))
			require.NoError(t, err)
			require.Equal(t, want, root)
		}
	})
}

// FuzzTreeOperations pushes leaves parsed from the fuzz input to trees with
// fuzzed options, including out-of-order and too-short leaves. It checks
// that Push accepts exactly the valid leaves, that the root's namespace range
// matches the pushed leaves, that ProveRange rejects exactly the invalid
// ranges, that every leaf and every namespace has a verifying proof, that a
// tree with ReuseBuffers gives the same results after Reset, and that
// ProveNamespace and ProveRange agree.
func FuzzTreeOperations(f *testing.F) {
	f.Add([]byte{})
	for _, seed := range randomSeeds(6, 16, 128, 1024, 4096) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		r := &byteReader{data: input}
		cfg := r.readByte()
		nsSize := fuzzNsSizes[int(cfg)%len(fuzzNsSizes)]
		ignoreMax := cfg&8 != 0
		reuse := cfg&16 != 0
		opts := []nmt.Option{
			nmt.NamespaceIDSize(nsSize),
			nmt.IgnoreMaxNamespace(ignoreMax),
			nmt.ReuseBuffers(reuse),
			nmt.InitialCapacity(int(r.readByte()) % 8),
		}
		tree := nmt.New(sha256.New(), opts...)

		var leaves [][]byte
		for i := int(r.readByte()) % 48; i > 0; i-- {
			var leaf []byte
			if r.readByte()%16 == 0 {
				leaf = r.read(int(r.readByte()) % (nsSize + 1)) // may be too short
			} else {
				leaf = append(r.read(nsSize), r.read(int(r.readByte())%8)...)
			}
			err := tree.Push(leaf)
			switch {
			case len(leaf) < nsSize:
				require.ErrorIs(t, err, nmt.ErrInvalidLeafLen)
			case len(leaves) > 0 && bytes.Compare(leaf[:nsSize], leaves[len(leaves)-1][:nsSize]) < 0:
				require.ErrorIs(t, err, nmt.ErrInvalidPushOrder)
			default:
				require.NoError(t, err)
				leaves = append(leaves, leaf)
			}
		}
		require.Equal(t, len(leaves), tree.Size())
		root, err := tree.Root()
		require.NoError(t, err)
		root = bytes.Clone(root)
		nth := nmt.NewNmtHasher(sha256.New(), namespace.IDSize(nsSize), ignoreMax)
		if len(leaves) == 0 {
			require.Equal(t, nth.EmptyRoot(), root)
		} else {
			wantMin, wantMax := expectedRootRange(leaves, nsSize, ignoreMax)
			minNs, err := tree.MinNamespace()
			require.NoError(t, err)
			maxNs, err := tree.MaxNamespace()
			require.NoError(t, err)
			require.Equal(t, wantMin, []byte(minNs))
			require.Equal(t, wantMax, []byte(maxNs))
		}

		start, end := int(int8(r.readByte())), int(int8(r.readByte()))
		if _, err := tree.ProveRange(start, end); start < 0 || start >= end || end > len(leaves) {
			require.ErrorIs(t, err, nmt.ErrInvalidRange)
		} else {
			require.NoError(t, err)
		}
		_, err = tree.Prove(len(leaves))
		require.ErrorIs(t, err, nmt.ErrInvalidRange)

		for i, leaf := range leaves {
			proof, err := tree.Prove(i)
			require.NoError(t, err)
			require.True(t, proof.VerifyInclusion(sha256.New(), leaf[:nsSize], [][]byte{leaf[nsSize:]}, root),
				"inclusion proof for leaf %d does not verify", i)
		}

		queries := make([][]byte, 0, 1+len(leaves))
		queries = append(queries, r.read(nsSize))
		for _, leaf := range leaves {
			queries = append(queries, leaf[:nsSize])
		}
		for _, nID := range queries {
			if ignoreMax && isMaxNamespace(nID) {
				continue // not queryable, see docs/nmt-lib.md
			}
			data, proof, err := tree.GetWithProof(nID)
			require.NoError(t, err)
			require.True(t, proof.VerifyNamespace(sha256.New(), nID, data, root),
				"namespace proof for %x does not verify", nID)
			if len(data) == 0 {
				continue
			}
			rangeProof, err := tree.ProveRange(proof.Start(), proof.End())
			require.NoError(t, err)
			require.True(t, equalByteSlices(proof.Nodes(), rangeProof.Nodes()),
				"ProveNamespace and ProveRange disagree for %x", nID)
		}

		// rebuilding after Reset gives the same root
		tree.Reset()
		require.Zero(t, tree.Size())
		for _, leaf := range leaves {
			require.NoError(t, tree.Push(leaf))
		}
		again, err := tree.Root()
		require.NoError(t, err)
		require.Equal(t, root, again)
	})
}

// expectedRootRange returns the namespace range the root of a tree with the
// given sorted leaves should carry. With ignoreMax, leaves with the maximum
// namespace do not raise the maximum unless all leaves have it.
func expectedRootRange(leaves [][]byte, nsSize int, ignoreMax bool) (minNs, maxNs []byte) {
	minNs = leaves[0][:nsSize]
	maxNs = leaves[len(leaves)-1][:nsSize]
	if ignoreMax && isMaxNamespace(maxNs) {
		for i := len(leaves) - 1; i >= 0; i-- {
			if !isMaxNamespace(leaves[i][:nsSize]) {
				return minNs, leaves[i][:nsSize]
			}
		}
	}
	return minNs, maxNs
}

// FuzzGetSubrootPaths checks that GetSubrootPaths does not panic on
// arbitrary input, and that on success the returned paths select subtrees
// that exactly cover the requested shares, row by row.
func FuzzGetSubrootPaths(f *testing.F) {
	f.Add(uint(2), uint(0), uint(1))
	f.Add(uint(8), uint(3), uint(20))
	f.Add(uint(16), uint(0), uint(256))
	f.Add(uint(64), uint(70), uint(5))
	f.Add(uint(3), uint(0), uint(1))
	f.Add(^uint(0), ^uint(0), uint(2))
	f.Fuzz(func(t *testing.T, squareSize, idxStart, shareCount uint) {
		// keep the output, which is linear in the number of rows, small
		if squareSize != 0 && shareCount/squareSize > 1<<12 {
			return
		}
		paths, err := nmt.GetSubrootPaths(squareSize, idxStart, shareCount)
		if err != nil {
			return
		}
		require.True(t, squareSize >= 2 && bits.OnesCount(squareSize) == 1)
		require.NotZero(t, shareCount)
		require.LessOrEqual(t, idxStart+shareCount, squareSize*squareSize)

		depth := bits.Len(squareSize) - 1
		startRow := idxStart / squareSize
		lastRow := (idxStart + shareCount - 1) / squareSize
		require.Len(t, paths, int(lastRow-startRow+1))
		for i, rowPaths := range paths {
			row := startRow + uint(i)
			first, last := uint(0), squareSize-1
			if row == startRow {
				first = idxStart % squareSize
			}
			if row == lastRow {
				last = (idxStart + shareCount - 1) % squareSize
			}
			// the paths may come in any order; sort the covered spans
			spans := make([][2]uint, 0, len(rowPaths))
			for _, path := range rowPaths {
				require.LessOrEqual(t, len(path), depth)
				prefix := uint(0)
				for _, bit := range path {
					require.Contains(t, []int{0, 1}, bit)
					prefix = prefix<<1 | uint(bit)
				}
				span := uint(1) << (depth - len(path))
				spans = append(spans, [2]uint{prefix * span, prefix*span + span})
			}
			sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
			cursor := first
			for _, span := range spans {
				require.Equal(t, cursor, span[0],
					"row %d: paths %v do not cover shares [%d, %d] exactly once", row, rowPaths, first, last)
				cursor = span[1]
			}
			require.Equal(t, last+1, cursor, "row %d: paths %v do not cover shares [%d, %d]", row, rowPaths, first, last)
		}
	})
}
