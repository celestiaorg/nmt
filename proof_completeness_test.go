package nmt

import (
	"crypto/sha256"
	"testing"

	"github.com/celestiaorg/nmt/namespace"
	"github.com/stretchr/testify/require"
)

// TestValidateCompleteness_TruncatedProof_RejectsEmptyNodes ensures that a
// proof whose nodes slice is empty (but whose start index is non-zero) is
// rejected. Before the fix, the left-traversal loop exited immediately on
// `len(nodes) > 0`, rightSubtrees became empty, and the function silently
// returned nil even though no completeness check was actually performed.
func TestValidateCompleteness_TruncatedProof_RejectsEmptyNodes(t *testing.T) {
	nth := NewNmtHasher(sha256.New(), namespace.IDSize(1), false)
	targetNID := namespace.ID{0x05}

	// start=8 requires the left traversal to walk indices [0, 8). With an
	// empty nodes slice, the loop cannot consume anything and leafIndex
	// stays at 0, never reaching proof.Start()=8.
	proof := Proof{
		start: 8,
		end:   9,
		nodes: nil,
	}

	err := proof.validateCompleteness(nth, targetNID)
	require.ErrorIs(t, err, ErrFailedCompletenessCheck,
		"validateCompleteness must reject a proof whose nodes are "+
			"exhausted before the left traversal reaches proof.Start()")
}

// TestValidateCompleteness_TruncatedProof_RejectsInsufficientNodes is the
// non-empty variant: the nodes slice has some entries but is still too short
// to carry the left traversal to proof.Start().
func TestValidateCompleteness_TruncatedProof_RejectsInsufficientNodes(t *testing.T) {
	nth := NewNmtHasher(sha256.New(), namespace.IDSize(1), false)
	targetNID := namespace.ID{0x05}

	// A single well-formed NMT node whose namespace range is [0x01, 0x01]
	// (strictly less than targetNID). As a leftSubtree this passes the
	// left-side check; it's only in the slice so the left traversal
	// consumes something before nodes are exhausted.
	smallNID := []byte{0x01}
	digest := sha256.Sum256([]byte("leftSubtreeNode"))
	node := append(append([]byte{}, smallNID...), smallNID...)
	node = append(node, digest[:]...)

	// For start=12:
	//   - iter 1: nextSubtreeSize(0, 12) = 8, consumes the only node,
	//             leafIndex advances to 8, nodes becomes empty.
	//   - iter 2: loop exits via len(nodes) > 0 == false,
	//             leafIndex=8 != proof.Start()=12.
	proof := Proof{
		start: 12,
		end:   13,
		nodes: [][]byte{node},
	}

	err := proof.validateCompleteness(nth, targetNID)
	require.ErrorIs(t, err, ErrFailedCompletenessCheck,
		"validateCompleteness must reject a proof whose nodes are "+
			"exhausted partway through the left traversal "+
			"(leafIndex stuck before proof.Start())")
}

// TestValidateCompleteness_RightSideCheck_StillRejectsSmallNamespace is a
// control test: it confirms the right-side namespace check itself still
// works and that the fix only rejects the truncated-proof case, not the
// well-formed case where start==0 and a right subtree's namespace is
// <= targetNID.
func TestValidateCompleteness_RightSideCheck_StillRejectsSmallNamespace(t *testing.T) {
	nth := NewNmtHasher(sha256.New(), namespace.IDSize(1), false)
	targetNID := namespace.ID{0x05}

	// Right subtree with min-namespace 0x01, which is <= targetNID 0x05,
	// so the right-side check must reject it.
	smallNID := []byte{0x01}
	digest := sha256.Sum256([]byte("rightSubtreeNode"))
	rightNode := append(append([]byte{}, smallNID...), smallNID...)
	rightNode = append(rightNode, digest[:]...)

	// start=0 means the left-traversal loop exits immediately with
	// leafIndex == proof.Start() == 0, so the new insufficiency check
	// does not trip. The sole node becomes a rightSubtree.
	proof := Proof{
		start: 0,
		end:   1,
		nodes: [][]byte{rightNode},
	}

	err := proof.validateCompleteness(nth, targetNID)
	require.ErrorIs(t, err, ErrFailedCompletenessCheck)
}
