package nmt

import (
	"bytes"
	"errors"
	"hash"

	"github.com/celestiaorg/celestia-core/pkg/consts"
	"github.com/celestiaorg/nmt/namespace"
	"github.com/tendermint/tendermint/crypto/tmhash"
)

type NamespaceMerkleTreeInclusionProof struct {
	// sibling hash values, ordered starting from the leaf's neighbor
	// array of 32-byte hashes
	SiblingValues [][]byte
	// sibling min namespace IDs
	// array of NAMESPACE_ID_BYTES-bytes
	SiblingMins [][]byte
	// sibling max namespace IDs
	// array of NAMESPACE_ID_BYTES-bytes
	SiblingMaxes [][]byte
}

func (nmtip *NamespaceMerkleTreeInclusionProof) ValidateBasic() error {
	// check if number of values and min/max namespaced provided by the proof match in numbers
	if len(nmtip.SiblingValues) != len(nmtip.SiblingMins) || len(nmtip.SiblingValues) != len(nmtip.SiblingMaxes) {
		return errors.New("Numbers of SiblingValues, SiblingMins and SiblingMaxes do not match.")
	}
	// check if the hash values have the correct byte size
	for _, siblingValue := range nmtip.SiblingValues {
		if len(siblingValue) != tmhash.Size {
			return errors.New("Number of hash bytes is incorrect.")
		}
	}
	// check if the namespaceIDs have the correct sizes
	for _, siblingMin := range nmtip.SiblingMins {
		if len(siblingMin) != consts.NamespaceSize {
			return errors.New("Number of namespace bytes is incorrect.")
		}
	}
	for _, siblingMax := range nmtip.SiblingMaxes {
		if len(siblingMax) != consts.NamespaceSize {
			return errors.New("Number of namespace bytes is incorrect.")
		}
	}
	return nil
}

func (n *NamespacedMerkleTree) CreateInclusionProof(idx int) (NamespaceMerkleTreeInclusionProof, error) {
	// todo(evan): reconsisder catching this panic
	if idx >= len(n.leaves) {
		return NamespaceMerkleTreeInclusionProof{}, errors.New("index greater than size of tree")
	}

	proof, err := n.Prove(idx)
	if err != nil {
		return NamespaceMerkleTreeInclusionProof{}, err
	}

	mins := make([][]byte, len(proof.nodes))
	maxs := make([][]byte, len(proof.nodes))
	// rawData := make([][]byte, len(proof.nodes))

	for i := 0; i < len(proof.nodes); i++ {
		mins[i] = proof.nodes[i][:n.NamespaceSize()]
		maxs[i] = proof.nodes[i][n.NamespaceSize() : n.NamespaceSize()*2]
		// rawData[i] = proof.nodes[i][n.NamespaceSize()*2:]
	}

	return NamespaceMerkleTreeInclusionProof{
		SiblingValues: proof.nodes,
		SiblingMins:   mins,
		SiblingMaxes:  maxs,
	}, nil
}

func VerifyInclusion(
	root namespace.IntervalDigest,
	hasher hash.Hash,
	proof NamespaceMerkleTreeInclusionProof,
	share []byte,
) (bool, error) {
	rawRoot := Root(defaultHasher, proof.SiblingValues)
	return bytes.Compare(root.Digest, rawRoot.Digest) == 0, nil
}

// Return the namespaced Merkle Tree's root together with the
// min. and max. namespace ID.
func Root(hasher *Hasher, leaves [][]byte) namespace.IntervalDigest {
	rawRoot := computeRoot(0, len(leaves), leaves, hasher)
	return mustIntervalDigestFromBytes(8, rawRoot)
}

func computeRoot(start, end int, leaveHashes [][]byte, treeHasher *Hasher) []byte {
	switch end - start {
	case 0:
		rootHash := treeHasher.EmptyRoot()
		return rootHash
	default:
		k := getSplitPoint(end - start)
		left := computeRoot(start, start+k, leaveHashes, treeHasher)
		right := computeRoot(start+k, end, leaveHashes, treeHasher)
		hash := treeHasher.HashNode(left, right)
		return hash
	}
}
