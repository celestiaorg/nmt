package nmt_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"math/bits"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/nmt"
	"github.com/celestiaorg/nmt/namespace"
	"github.com/celestiaorg/nmt/pb"
)

// FuzzVerifyArbitraryProof feeds proofs, leaves, leaf hashes, roots and
// subtree widths parsed from the raw fuzz input to every verification API.
// Malformed input must make verification fail or return an error, never
// panic. It also checks that ComputeRootWithBasicValidation and
// VerifyLeafHashes agree, and that a proof survives a JSON round trip.
func FuzzVerifyArbitraryProof(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0}, 128))
	f.Add(bytes.Repeat([]byte{0xFF}, 512))
	for _, seed := range randomSeeds(2, 64, 256, 1024, 4096) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		r := &byteReader{data: input}
		nsSize := fuzzNsSizes[int(r.readByte())%len(fuzzNsSizes)]
		nodeSize := 2*nsSize + sha256.Size
		flags := r.readByte()
		ignoreMax := flags&1 != 0

		start, end := r.readIndex(), r.readIndex()
		nodes := r.readNodes(nodeSize, 32)
		var leafHash []byte
		if flags&2 != 0 {
			leafHash = r.readNode(nodeSize)
		}
		nID := namespace.ID(r.read(nsSize))
		if flags&4 != 0 {
			// a namespace whose size does not match the proof nodes
			nID = namespace.ID(r.read(int(r.readByte()) % 40))
		}
		root := r.readNode(nodeSize)
		leafHashes := r.readNodes(nodeSize, 16)
		leaves := make([][]byte, int(r.readByte())%17)
		for i := range leaves {
			if r.readByte()%4 != 0 {
				leaves[i] = append(bytes.Clone(nID), r.read(int(r.readByte())%64)...)
			} else {
				leaves[i] = r.read(int(r.readByte()) % 64)
			}
		}
		width := r.readIndex()

		proof := nmt.NewAbsenceProof(start, end, nodes, leafHash, ignoreMax)
		require.Equal(t, len(leafHash) > 0, proof.IsOfAbsence())
		require.Equal(t, start == end && len(nodes) == 0 && len(leafHash) == 0, proof.IsEmptyProof())
		require.Equal(t, start >= 0 && start < end, proof.IsNonEmptyRange())

		proof.VerifyNamespace(sha256.New(), nID, leaves, root)
		proof.VerifyInclusion(sha256.New(), nID, leaves, root)

		// The hasher-based APIs are documented to take a hasher whose
		// namespace size matches nID, so build it from nID.
		nth := nmt.NewNmtHasher(sha256.New(), nID.Size(), ignoreMax)
		_, _ = nmt.ComputeAndValidateLeafHashes(nth, nID, leaves)
		_, _ = nmt.ComputePrefixedLeafHashes(nth, nID, leaves)
		for _, check := range []bool{false, true} {
			ok, err := proof.VerifyLeafHashes(nth, check, nID, leafHashes, root)
			if ok {
				require.NoError(t, err)
			}
			computed, err := proof.ComputeRootWithBasicValidation(nth, nID, leafHashes, check)
			if err != nil || (!check && !proof.IsOfAbsence()) {
				// VerifyLeafHashes checks the leaf namespaces of a
				// non-absence proof even without completeness, while
				// ComputeRootWithBasicValidation(isNamespace=false) does not.
				continue
			}
			// a root computed with full validation must verify the same proof
			ok, err = proof.VerifyLeafHashes(nth, check, nID, leafHashes, computed)
			require.NoError(t, err)
			require.True(t, ok, "ComputeRootWithBasicValidation and VerifyLeafHashes disagree")
		}
		ok, err := proof.VerifySubtreeRootInclusion(nth, leafHashes, width, root)
		if ok {
			require.NoError(t, err)
		}

		// ToLeafRanges does one step per output range, so keep the span small.
		if start >= 0 && end > start && end-start <= 1<<12 {
			ranges, err := nmt.ToLeafRanges(start, end, width)
			if err == nil {
				checkLeafRanges(t, ranges, start, end, width)
			}
		}

		checkJSONRoundTrip(t, proof)
	})
}

// checkLeafRanges checks that ranges cover [start, end) contiguously with
// aligned power-of-two subtrees no wider than width.
func checkLeafRanges(t *testing.T, ranges []nmt.LeafRange, start, end, width int) {
	t.Helper()
	require.NotEmpty(t, ranges)
	cursor := start
	for _, rng := range ranges {
		size := rng.End - rng.Start
		require.Equal(t, cursor, rng.Start, "ranges are not contiguous: %v", ranges)
		require.Positive(t, size)
		require.LessOrEqual(t, size, width)
		require.Equal(t, 1, bits.OnesCount(uint(size)), "range size %d is not a power of two", size)
		require.Zero(t, rng.Start%size, "range %v is not aligned", rng)
		cursor = rng.End
	}
	require.Equal(t, end, cursor, "ranges do not cover [%d, %d): %v", start, end, ranges)
}

// checkJSONRoundTrip checks that a proof decodes to the same fields it was
// encoded from.
func checkJSONRoundTrip(t *testing.T, proof nmt.Proof) {
	t.Helper()
	encoded, err := json.Marshal(proof)
	require.NoError(t, err)
	var decoded nmt.Proof
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, proof.Start(), decoded.Start())
	require.Equal(t, proof.End(), decoded.End())
	require.True(t, equalByteSlices(proof.Nodes(), decoded.Nodes()))
	require.True(t, bytes.Equal(proof.LeafHash(), decoded.LeafHash()))
	require.Equal(t, proof.IsMaxNamespaceIDIgnored(), decoded.IsMaxNamespaceIDIgnored())
}

// FuzzProofDecode decodes raw bytes as a protobuf proof and as a JSON proof.
// Decoding must not panic. A decoded protobuf proof must re-encode
// deterministically, ProtoToProof must keep its fields (except for the
// (0, 0) range, which becomes the empty proof), and the resulting proof must
// survive a JSON round trip and be safe to verify.
func FuzzProofDecode(f *testing.F) {
	tree := nmt.New(sha256.New(), nmt.NamespaceIDSize(1))
	for i := byte(0); i < 6; i++ {
		require.NoError(f, tree.Push([]byte{i, i}))
	}
	for _, nID := range []byte{2, 7} {
		proof, err := tree.ProveNamespace(namespace.ID{nID})
		require.NoError(f, err)
		pbProof := pb.Proof{
			Start:                 int64(proof.Start()),
			End:                   int64(proof.End()),
			Nodes:                 proof.Nodes(),
			LeafHash:              proof.LeafHash(),
			IsMaxNamespaceIgnored: proof.IsMaxNamespaceIDIgnored(),
		}
		encoded, err := pbProof.Marshal()
		require.NoError(f, err)
		f.Add(encoded)
		jsonProof, err := json.Marshal(proof)
		require.NoError(f, err)
		f.Add(jsonProof)
	}
	f.Add([]byte{})
	f.Add([]byte(`{"start":-1,"end":9223372036854775807,"nodes":[""],"leaf_hash":"AA==","is_max_namespace_ignored":true}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		var fromJSON nmt.Proof
		if err := json.Unmarshal(input, &fromJSON); err == nil {
			checkJSONRoundTrip(t, fromJSON)
			verifyAgainstOwnNodes(fromJSON)
		}

		var pbProof pb.Proof
		if err := pbProof.Unmarshal(input); err != nil {
			return
		}
		encoded, err := pbProof.Marshal()
		require.NoError(t, err)
		var again pb.Proof
		require.NoError(t, again.Unmarshal(encoded))
		reencoded, err := again.Marshal()
		require.NoError(t, err)
		require.Equal(t, encoded, reencoded, "protobuf encoding is not stable")

		proof := nmt.ProtoToProof(pbProof)
		require.Equal(t, pbProof.IsMaxNamespaceIgnored, proof.IsMaxNamespaceIDIgnored())
		if pbProof.Start == 0 && pbProof.End == 0 {
			require.True(t, proof.IsEmptyProof())
		} else {
			require.Equal(t, int(pbProof.Start), proof.Start())
			require.Equal(t, int(pbProof.End), proof.End())
			require.True(t, equalByteSlices(pbProof.Nodes, proof.Nodes()))
			require.True(t, bytes.Equal(pbProof.LeafHash, proof.LeafHash()))
		}
		checkJSONRoundTrip(t, proof)
		verifyAgainstOwnNodes(proof)
	})
}

// verifyAgainstOwnNodes runs the verification APIs on a decoded proof, using
// its own nodes as roots and leaf hashes, so that decoded proofs reach the
// verifier. Only the absence of panics is checked.
func verifyAgainstOwnNodes(proof nmt.Proof) {
	candidates := append([][]byte{proof.LeafHash()}, proof.Nodes()...)
	for _, root := range candidates {
		for _, nsSize := range []int{0, 1, 29} {
			if len(root) < nsSize {
				continue
			}
			nID := namespace.ID(root[:nsSize])
			proof.VerifyNamespace(sha256.New(), nID, nil, root)
			proof.VerifyNamespace(sha256.New(), nID, [][]byte{root}, root)
			proof.VerifyInclusion(sha256.New(), nID, [][]byte{root}, root)
			nth := nmt.NewNmtHasher(sha256.New(), namespace.IDSize(nsSize), proof.IsMaxNamespaceIDIgnored())
			_, _ = proof.VerifyLeafHashes(nth, true, nID, candidates, root)
			_, _ = proof.VerifySubtreeRootInclusion(nth, candidates, 1, root)
		}
	}
}

// FuzzNamespaceProofSoundness builds a tree, takes an honest namespace proof
// and checks that it verifies (completeness). It then changes the proof, the
// leaves or the namespace, and checks that VerifyNamespace only accepts the
// result if the claimed leaves are exactly the leaves of that namespace in
// the tree (soundness).
func FuzzNamespaceProofSoundness(f *testing.F) {
	f.Add([]byte{})
	for _, seed := range randomSeeds(3, 32, 256, 1024, 4096) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		r := &byteReader{data: input}
		cfg := r.readByte()
		nsSize := []int{1, 2, 8}[int(cfg)%3]
		ignoreMax := cfg&4 != 0
		leaves := r.readSortedLeaves(nsSize, 64, 16)
		ft := buildFuzzTree(t, leaves, nsSize, ignoreMax)

		var nID namespace.ID
		if len(leaves) > 0 && r.readByte()%2 == 0 {
			nID = namespace.ID(bytes.Clone(leaves[int(r.readByte())%len(leaves)][:nsSize]))
		} else {
			nID = namespace.ID(r.read(nsSize))
		}
		// The maximum namespace is reserved for parity data and is not
		// queryable when the tree ignores it (see docs/nmt-lib.md).
		if ignoreMax && isMaxNamespace(nID) {
			return
		}
		proof, err := ft.tree.ProveNamespace(nID)
		require.NoError(t, err)
		data := ft.tree.Get(nID)
		require.True(t, proof.VerifyNamespace(sha256.New(), nID, data, ft.root),
			"honest namespace proof does not verify")

		candidates := append(ft.subtreeRoots(t), ft.leafHashes...)
		parts := partsOf(proof)
		claimedNID := bytes.Clone(nID)
		claimed := cloneByteSlices(data)
		for n := 1 + int(r.readByte())%3; n > 0; n-- {
			switch r.readByte() % 4 {
			case 0, 1:
				parts.mutate(r, candidates)
			case 2:
				claimed = mutateLeaves(r, claimed, leaves)
			case 3:
				claimedNID = flipBit(claimedNID, r.readUint16())
			}
		}
		mutated := parts.proof()
		if mutated.IsOfAbsence() {
			// VerifyNamespace documents that leaves are empty for an
			// absence proof.
			claimed = nil
		}
		if !mutated.VerifyNamespace(sha256.New(), claimedNID, claimed, ft.root) {
			return
		}
		if ignoreMax && isMaxNamespace(claimedNID) {
			return
		}
		want := ft.tree.Get(claimedNID)
		require.True(t, equalByteSlices(want, claimed),
			"VerifyNamespace accepted wrong leaves for namespace %x: got %x, want %x (proof %+v)",
			[]byte(claimedNID), claimed, want, parts)
	})
}

// mutateLeaves applies one change, chosen by r, to a list of claimed leaves.
func mutateLeaves(r *byteReader, claimed, treeLeaves [][]byte) [][]byte {
	claimed = cloneByteSlices(claimed)
	switch r.readByte() % 5 {
	case 0: // drop a leaf
		if len(claimed) > 0 {
			i := int(r.readByte()) % len(claimed)
			claimed = append(claimed[:i:i], claimed[i+1:]...)
		}
	case 1: // insert a leaf from the tree
		if len(treeLeaves) > 0 {
			leaf := bytes.Clone(treeLeaves[int(r.readByte())%len(treeLeaves)])
			i := int(r.readByte()) % (len(claimed) + 1)
			claimed = append(claimed[:i:i], append([][]byte{leaf}, claimed[i:]...)...)
		}
	case 2: // flip a bit in a leaf
		if len(claimed) > 0 {
			i := int(r.readByte()) % len(claimed)
			claimed[i] = flipBit(claimed[i], r.readUint16())
		}
	case 3: // swap two leaves
		if len(claimed) > 1 {
			i, j := int(r.readByte())%len(claimed), int(r.readByte())%len(claimed)
			claimed[i], claimed[j] = claimed[j], claimed[i]
		}
	case 4: // duplicate a leaf
		if len(claimed) > 0 {
			i := int(r.readByte()) % len(claimed)
			claimed = append(claimed[:i+1:i+1], claimed[i:]...)
		}
	}
	return claimed
}

// FuzzRangeProofSoundness builds a tree, takes an honest range proof for an
// arbitrary range and checks that it verifies (completeness), and that
// ProveNamespace and ProveRange agree for single-namespace ranges. It then
// changes the proof or the claimed leaf hashes, and checks that a proof that
// still reproduces the root claims a run of leaves that really is in the tree,
// at the claimed position when the claimed range lies in the tree.
func FuzzRangeProofSoundness(f *testing.F) {
	f.Add([]byte{})
	for _, seed := range randomSeeds(4, 32, 256, 1024, 4096) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		r := &byteReader{data: input}
		cfg := r.readByte()
		nsSize := []int{1, 2, 8}[int(cfg)%3]
		ignoreMax := cfg&4 != 0
		leaves := r.readSortedLeaves(nsSize, 64, 8)
		if cfg&8 != 0 && len(leaves) > 0 {
			// Celestia rows are powers of two
			leaves = leaves[:1<<(bits.Len(uint(len(leaves)))-1)]
		}
		ft := buildFuzzTree(t, leaves, nsSize, ignoreMax)
		n := len(leaves)

		// mostly valid ranges, sometimes arbitrary ones
		start := int(r.readByte()) % (n + 1)
		end := start + 1 + int(r.readByte())%(n-start+1)
		if r.readByte()%8 == 0 {
			start, end = int(int8(r.readByte())), int(int8(r.readByte()))
		}
		proof, err := ft.tree.ProveRange(start, end)
		if start < 0 || start >= end || end > n {
			require.ErrorIs(t, err, nmt.ErrInvalidRange)
			return
		}
		require.NoError(t, err)

		nth := nmt.NewNmtHasher(sha256.New(), namespace.IDSize(nsSize), ignoreMax)
		nID := namespace.ID(leaves[start][:nsSize])
		root, err := proof.ComputeRootWithBasicValidation(nth, nID, ft.leafHashes[start:end], false)
		require.NoError(t, err)
		require.Equal(t, ft.root, root, "honest range proof does not reproduce the root")

		if sameNamespace(leaves[start:end], nsSize) {
			raw := make([][]byte, 0, end-start)
			for _, leaf := range leaves[start:end] {
				raw = append(raw, leaf[nsSize:])
			}
			require.True(t, proof.VerifyInclusion(sha256.New(), nID, raw, ft.root))
			nsStart, nsEnd := namespaceRange(leaves, nID, nsSize)
			if nsStart == start && nsEnd == end && (!ignoreMax || !isMaxNamespace(nID)) {
				nsProof, err := ft.tree.ProveNamespace(nID)
				require.NoError(t, err)
				require.True(t, equalByteSlices(proof.Nodes(), nsProof.Nodes()),
					"ProveRange and ProveNamespace disagree")
				require.Equal(t, proof.Start(), nsProof.Start())
				require.Equal(t, proof.End(), nsProof.End())
			}
		}

		candidates := append(ft.subtreeRoots(t), ft.leafHashes...)
		parts := partsOf(proof)
		parts.leafHash = nil
		claimed := cloneByteSlices(ft.leafHashes[start:end])
		for k := 1 + int(r.readByte())%3; k > 0; k-- {
			if r.readByte()%3 == 0 {
				claimed = mutateLeaves(r, claimed, ft.leafHashes)
			} else {
				parts.mutate(r, candidates)
			}
		}
		parts.leafHash = nil
		mutated := parts.proof()
		got, err := mutated.ComputeRootWithBasicValidation(nth, nID, claimed, false)
		if err != nil || !bytes.Equal(got, ft.root) {
			return
		}
		require.True(t, containsRun(ft.leafHashes, claimed),
			"a changed range proof reproduces the root for leaf hashes that are not a run of tree leaves (proof %+v)", parts)
		if isPowerOfTwo(n) && mutated.End() <= n {
			require.True(t, equalByteSlices(ft.leafHashes[mutated.Start():mutated.End()], claimed),
				"a changed range proof [%d, %d) verifies for leaves at another position", mutated.Start(), mutated.End())
		}
	})
}

func sameNamespace(leaves [][]byte, nsSize int) bool {
	for _, leaf := range leaves {
		if !bytes.Equal(leaf[:nsSize], leaves[0][:nsSize]) {
			return false
		}
	}
	return true
}

// namespaceRange returns the range of leaves with namespace nID.
func namespaceRange(leaves [][]byte, nID []byte, nsSize int) (int, int) {
	start, end := -1, -1
	for i, leaf := range leaves {
		if bytes.Equal(leaf[:nsSize], nID) {
			if start < 0 {
				start = i
			}
			end = i + 1
		}
	}
	return start, end
}

// containsRun reports whether run occurs as a contiguous sub-list of list.
func containsRun(list, run [][]byte) bool {
	for i := 0; i+len(run) <= len(list); i++ {
		if equalByteSlices(list[i:i+len(run)], run) {
			return true
		}
	}
	return false
}

func isPowerOfTwo(n int) bool {
	return n > 0 && n&(n-1) == 0
}

// FuzzSubtreeRootInclusion builds a power-of-two tree, splits an arbitrary
// range into subtree roots with ToLeafRanges and ComputeSubtreeRoot, and
// checks that VerifySubtreeRootInclusion accepts the honest proof
// (completeness) and rejects it after any change to a subtree root or proof
// node (soundness).
func FuzzSubtreeRootInclusion(f *testing.F) {
	f.Add([]byte{})
	for _, seed := range randomSeeds(5, 16, 128, 1024) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		r := &byteReader{data: input}
		cfg := r.readByte()
		nsSize := []int{1, 8, 29}[int(cfg)%3]
		ignoreMax := cfg&4 != 0
		n := 1 << (r.readByte() % 7)
		leaves := make([][]byte, n)
		for i := range leaves {
			leaves[i] = append(r.read(nsSize), r.read(int(r.readByte())%8)...)
		}
		leaves = sortedLeaves(leaves, nsSize)
		ft := buildFuzzTree(t, leaves, nsSize, ignoreMax)

		start := int(r.readByte()) % n
		end := start + 1 + int(r.readByte())%(n-start)
		width := 1 << (r.readByte() % 8)
		ranges, err := nmt.ToLeafRanges(start, end, width)
		if err != nil {
			// only unaligned ranges are rejected
			require.ErrorContains(t, err, "doesn't allow creating a valid leaf range")
			return
		}
		checkLeafRanges(t, ranges, start, end, width)
		roots := make([][]byte, len(ranges))
		for i, rng := range ranges {
			roots[i], err = ft.tree.ComputeSubtreeRoot(rng.Start, rng.End)
			require.NoError(t, err)
		}
		proof, err := ft.tree.ProveRange(start, end)
		require.NoError(t, err)
		nth := nmt.NewNmtHasher(sha256.New(), namespace.IDSize(nsSize), ignoreMax)
		ok, err := proof.VerifySubtreeRootInclusion(nth, roots, width, ft.root)
		require.NoError(t, err)
		require.True(t, ok, "honest subtree root proof does not verify")

		// change one subtree root or proof node
		parts := partsOf(proof)
		roots = cloneByteSlices(roots)
		if r.readByte()%2 == 0 || len(parts.nodes) == 0 {
			i := int(r.readByte()) % len(roots)
			roots[i] = flipBit(roots[i], r.readUint16())
		} else {
			i := int(r.readByte()) % len(parts.nodes)
			parts.nodes[i] = flipBit(parts.nodes[i], r.readUint16())
		}
		ok, err = parts.proof().VerifySubtreeRootInclusion(nth, roots, width, ft.root)
		require.False(t, ok && err == nil, "changed subtree root proof verifies")
	})
}

func sortedLeaves(leaves [][]byte, nsSize int) [][]byte {
	sort.SliceStable(leaves, func(i, j int) bool {
		return bytes.Compare(leaves[i][:nsSize], leaves[j][:nsSize]) < 0
	})
	return leaves
}

// TestProofProtoBinaryRoundTrip checks that empty, inclusion and absence
// proofs still verify after a protobuf binary round trip, and that every
// truncation of an encoded proof either fails to decode or decodes without
// panicking.
func TestProofProtoBinaryRoundTrip(t *testing.T) {
	tree := nmt.New(sha256.New(), nmt.NamespaceIDSize(1))
	for _, leaf := range [][]byte{{1, 'a'}, {1, 'b'}, {3, 'c'}, {4, 'd'}, {6, 'e'}} {
		require.NoError(t, tree.Push(leaf))
	}
	root, err := tree.Root()
	require.NoError(t, err)

	for _, nID := range []namespace.ID{{0}, {1}, {2}, {4}, {5}, {9}} {
		data, proof, err := tree.GetWithProof(nID)
		require.NoError(t, err)
		encoded, err := (&pb.Proof{
			Start:                 int64(proof.Start()),
			End:                   int64(proof.End()),
			Nodes:                 proof.Nodes(),
			LeafHash:              proof.LeafHash(),
			IsMaxNamespaceIgnored: proof.IsMaxNamespaceIDIgnored(),
		}).Marshal()
		require.NoError(t, err)

		var decoded pb.Proof
		require.NoError(t, decoded.Unmarshal(encoded))
		got := nmt.ProtoToProof(decoded)
		require.True(t, got.VerifyNamespace(sha256.New(), nID, data, root), "namespace %x", nID)
		require.Equal(t, proof.IsOfAbsence(), got.IsOfAbsence())
		require.Equal(t, proof.IsEmptyProof(), got.IsEmptyProof())

		for i := 0; i < len(encoded); i++ {
			var truncated pb.Proof
			if truncated.Unmarshal(encoded[:i]) == nil {
				verifyAgainstOwnNodes(nmt.ProtoToProof(truncated))
			}
		}
	}
}
