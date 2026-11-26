package nmt_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"sort"
	"testing"

	"github.com/celestiaorg/nmt"
	"github.com/celestiaorg/nmt/namespace"
)

// fuzzNsSizes are the namespace sizes the fuzz targets pick from. Size 1 makes
// namespace collisions and the maximum namespace (0xFF) common, 29 is the size
// Celestia uses, and 0 is the degenerate non-namespaced tree.
var fuzzNsSizes = []int{0, 1, 2, 8, 29}

// randomSeeds returns deterministic pseudo-random seed inputs of the given
// lengths, used to give the fuzzers a varied starting corpus.
func randomSeeds(seed int64, lengths ...int) [][]byte {
	rng := rand.New(rand.NewSource(seed))
	seeds := make([][]byte, 0, len(lengths))
	for _, l := range lengths {
		b := make([]byte, l)
		rng.Read(b)
		seeds = append(seeds, b)
	}
	return seeds
}

// readUint16 reads a big-endian uint16 from r.
func (r *byteReader) readUint16() int {
	return int(binary.BigEndian.Uint16(r.read(2)))
}

// readIndex reads a proof index. Most of the time it is a small signed value
// so that ranges stay near real trees, but it can also be any int64 or a value
// near a power of two, to reach overflow and bounds checks.
func (r *byteReader) readIndex() int {
	switch mode := r.readByte() % 8; mode {
	case 6:
		return int(int64(binary.BigEndian.Uint64(r.read(8))))
	case 7:
		shift := r.readByte() % 63
		return 1<<shift + int(int8(r.readByte()))
	default:
		return int(int8(r.readByte()))
	}
}

// readDelta reads a signed offset that is usually small.
func (r *byteReader) readDelta() int {
	b := r.readByte()
	if b&0x80 != 0 {
		return int(int8(b))
	}
	return int(b%17) - 8
}

// readNode reads a byte slice that usually has the namespaced hash size of
// the given hasher, but sometimes has an arbitrary length.
func (r *byteReader) readNode(nodeSize int) []byte {
	if r.readByte()%8 == 0 {
		return r.read(int(r.readByte()) % (nodeSize + 8))
	}
	return r.read(nodeSize)
}

// readNodes reads up to maxCount nodes with readNode.
func (r *byteReader) readNodes(nodeSize, maxCount int) [][]byte {
	count := int(r.readByte()) % (maxCount + 1)
	if count == 0 {
		return nil
	}
	nodes := make([][]byte, count)
	for i := range nodes {
		nodes[i] = r.readNode(nodeSize)
	}
	return nodes
}

// fuzzTree is a tree built from fuzz input, plus the data needed to check
// claims against it.
type fuzzTree struct {
	tree       *nmt.NamespacedMerkleTree
	nsSize     int
	ignoreMax  bool
	leaves     [][]byte
	leafHashes [][]byte
	root       []byte
}

// buildFuzzTree pushes leaves to a new tree and computes its root and leaf
// hashes.
func buildFuzzTree(t *testing.T, leaves [][]byte, nsSize int, ignoreMax bool) *fuzzTree {
	t.Helper()
	tree := nmt.New(sha256.New(), nmt.NamespaceIDSize(nsSize), nmt.IgnoreMaxNamespace(ignoreMax))
	nth := nmt.NewNmtHasher(sha256.New(), namespace.IDSize(nsSize), ignoreMax)
	leafHashes := make([][]byte, 0, len(leaves))
	for _, leaf := range leaves {
		if err := tree.Push(leaf); err != nil {
			t.Fatalf("Push(%x): %v", leaf, err)
		}
		leafHashes = append(leafHashes, nth.MustHashLeaf(leaf))
	}
	root, err := tree.Root()
	if err != nil {
		t.Fatalf("Root(): %v", err)
	}
	return &fuzzTree{
		tree:       tree,
		nsSize:     nsSize,
		ignoreMax:  ignoreMax,
		leaves:     leaves,
		leafHashes: leafHashes,
		root:       root,
	}
}

// readSortedLeaves reads up to maxLeaves namespaced leaves from r and sorts
// them by namespace so they can be pushed to a tree.
func (r *byteReader) readSortedLeaves(nsSize, maxLeaves, maxPayload int) [][]byte {
	count := int(r.readByte()) % (maxLeaves + 1)
	leaves := make([][]byte, count)
	for i := range leaves {
		ns := r.read(nsSize)
		payload := r.read(int(r.readByte()) % (maxPayload + 1))
		leaves[i] = append(ns, payload...)
	}
	sort.SliceStable(leaves, func(i, j int) bool {
		return bytes.Compare(leaves[i][:nsSize], leaves[j][:nsSize]) < 0
	})
	return leaves
}

// isMaxNamespace reports whether nID is the all-0xFF namespace.
func isMaxNamespace(nID []byte) bool {
	return len(nID) > 0 && bytes.Count(nID, []byte{0xFF}) == len(nID)
}

// equalByteSlices compares two lists of byte slices, treating nil and empty
// slices as equal.
func equalByteSlices(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// cloneByteSlices deep-copies a list of byte slices.
func cloneByteSlices(s [][]byte) [][]byte {
	if s == nil {
		return nil
	}
	out := make([][]byte, len(s))
	for i := range s {
		out[i] = bytes.Clone(s[i])
	}
	return out
}

// flipBit flips one bit of b, chosen by sel. It returns b unchanged if b is
// empty.
func flipBit(b []byte, sel int) []byte {
	if len(b) == 0 {
		return b
	}
	out := bytes.Clone(b)
	bit := sel % (len(out) * 8)
	out[bit/8] ^= 1 << (bit % 8)
	return out
}

// proofParts holds the fields of a proof so that fuzz targets can change them
// one at a time.
type proofParts struct {
	start, end int
	nodes      [][]byte
	leafHash   []byte
	ignoreMax  bool
}

func partsOf(p nmt.Proof) proofParts {
	return proofParts{
		start:     p.Start(),
		end:       p.End(),
		nodes:     cloneByteSlices(p.Nodes()),
		leafHash:  bytes.Clone(p.LeafHash()),
		ignoreMax: p.IsMaxNamespaceIDIgnored(),
	}
}

func (pp proofParts) proof() nmt.Proof {
	return nmt.NewAbsenceProof(pp.start, pp.end, pp.nodes, pp.leafHash, pp.ignoreMax)
}

// mutate applies one change, chosen by r, to the proof parts. Candidates are
// extra valid-looking nodes (e.g. real leaf hashes and subtree roots) that can
// be spliced into the proof.
func (pp *proofParts) mutate(r *byteReader, candidates [][]byte) {
	pick := func(list [][]byte) int { return int(r.readByte()) % len(list) }
	switch r.readByte() % 10 {
	case 0: // flip a bit in a node
		if len(pp.nodes) > 0 {
			i := pick(pp.nodes)
			pp.nodes[i] = flipBit(pp.nodes[i], r.readUint16())
		}
	case 1: // drop a node
		if len(pp.nodes) > 0 {
			i := pick(pp.nodes)
			pp.nodes = append(pp.nodes[:i:i], pp.nodes[i+1:]...)
		}
	case 2: // insert a candidate node
		if len(candidates) > 0 {
			node := bytes.Clone(candidates[pick(candidates)])
			i := int(r.readByte()) % (len(pp.nodes) + 1)
			pp.nodes = append(pp.nodes[:i:i], append([][]byte{node}, pp.nodes[i:]...)...)
		}
	case 3: // replace a node with a candidate
		if len(pp.nodes) > 0 && len(candidates) > 0 {
			pp.nodes[pick(pp.nodes)] = bytes.Clone(candidates[pick(candidates)])
		}
	case 4: // swap two nodes
		if len(pp.nodes) > 1 {
			i, j := pick(pp.nodes), pick(pp.nodes)
			pp.nodes[i], pp.nodes[j] = pp.nodes[j], pp.nodes[i]
		}
	case 5: // move start
		pp.start += r.readDelta()
	case 6: // move end
		pp.end += r.readDelta()
	case 7: // shift the whole range
		d := r.readDelta()
		pp.start += d
		pp.end += d
	case 8: // flip the ignore max namespace flag
		pp.ignoreMax = !pp.ignoreMax
	case 9: // change the absence leaf hash
		switch {
		case len(pp.leafHash) > 0 && r.readByte()%2 == 0:
			pp.leafHash = flipBit(pp.leafHash, r.readUint16())
		case len(pp.leafHash) > 0:
			pp.leafHash = nil
		case len(candidates) > 0:
			pp.leafHash = bytes.Clone(candidates[pick(candidates)])
		}
	}
}

// subtreeRoots returns the roots of all aligned power-of-two subtrees of the
// tree, which are valid-looking nodes to splice into proofs.
func (ft *fuzzTree) subtreeRoots(t *testing.T) [][]byte {
	t.Helper()
	var roots [][]byte
	n := len(ft.leaves)
	for width := 1; width <= n; width *= 2 {
		for start := 0; start+width <= n; start += width {
			root, err := ft.tree.ComputeSubtreeRoot(start, start+width)
			if err != nil {
				t.Fatalf("ComputeSubtreeRoot(%d, %d): %v", start, start+width, err)
			}
			roots = append(roots, root)
		}
	}
	return roots
}
