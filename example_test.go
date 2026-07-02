package nmt_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/celestiaorg/nmt"
	"github.com/celestiaorg/nmt/namespace"
)

// ExampleProof_VerifyNamespace generates a namespace proof for the tree shown
// in Figure 1 of docs/spec/nmt.md and verifies it. The two proof nodes are the
// namespaced hashes of the subtree covering leaves 0-1 (the left sibling of
// the branch connecting leaf 2 to the root) and of leaf 3 (the right sibling),
// ordered by an in-order traversal of the tree. See docs/proof-format.md for
// details on the proof format.
func ExampleProof_VerifyNamespace() {
	// leaves are prefixed with their namespace ID before being pushed
	leaves := [][]byte{
		append(namespace.ID{0}, []byte("leaf_0")...),
		append(namespace.ID{0}, []byte("leaf_1")...),
		append(namespace.ID{1}, []byte("leaf_2")...),
		append(namespace.ID{3}, []byte("leaf_3")...),
	}
	tree := nmt.New(sha256.New(), nmt.NamespaceIDSize(1))
	for _, leaf := range leaves {
		if err := tree.Push(leaf); err != nil {
			panic(err)
		}
	}
	root, err := tree.Root()
	if err != nil {
		panic(err)
	}

	nID := namespace.ID{1}
	proof, err := tree.ProveNamespace(nID)
	if err != nil {
		panic(err)
	}
	fmt.Printf("proof range: [%d, %d)\n", proof.Start(), proof.End())
	for i, node := range proof.Nodes() {
		fmt.Printf("proof node %d: %x\n", i, node)
	}

	// verification requires the complete set of leaves (namespace-prefixed)
	// that match the queried namespace ID
	valid := proof.VerifyNamespace(sha256.New(), nID, leaves[proof.Start():proof.End()], root)
	fmt.Printf("valid: %v\n", valid)
	// Output:
	// proof range: [2, 3)
	// proof node 0: 0000ead8d25851870e4e7b5e8e4d10092df495a0d73af6fec3709ac79fa6338f57ae
	// proof node 1: 0303b4a27922d95e91d4a566aaadcedf5026b620022715910a354184c0af384e1440
	// valid: true
}

// ExampleProof_VerifyInclusion generates an index-based Merkle inclusion proof
// for the leaf at index 2 of the tree shown in Figure 1 of docs/spec/nmt.md
// and verifies it against the root. Note that VerifyInclusion takes the raw
// leaf data without the namespace prefix.
func ExampleProof_VerifyInclusion() {
	leaves := [][]byte{
		append(namespace.ID{0}, []byte("leaf_0")...),
		append(namespace.ID{0}, []byte("leaf_1")...),
		append(namespace.ID{1}, []byte("leaf_2")...),
		append(namespace.ID{3}, []byte("leaf_3")...),
	}
	tree := nmt.New(sha256.New(), nmt.NamespaceIDSize(1))
	for _, leaf := range leaves {
		if err := tree.Push(leaf); err != nil {
			panic(err)
		}
	}
	root, err := tree.Root()
	if err != nil {
		panic(err)
	}

	proof, err := tree.Prove(2)
	if err != nil {
		panic(err)
	}

	// the leaf data is provided without the namespace prefix; the namespace ID
	// is passed separately and applies to all leaves in the proof range
	rawLeaves := [][]byte{[]byte("leaf_2")}
	valid := proof.VerifyInclusion(sha256.New(), namespace.ID{1}, rawLeaves, root)
	fmt.Printf("valid: %v\n", valid)
	// Output:
	// valid: true
}

// ExampleProof_MarshalJSON shows the JSON serialization of a namespace proof.
// Nodes are base64-encoded namespaced hashes and zero-valued fields are
// omitted. See docs/proof-format.md for details.
func ExampleProof_MarshalJSON() {
	leaves := [][]byte{
		append(namespace.ID{0}, []byte("leaf_0")...),
		append(namespace.ID{0}, []byte("leaf_1")...),
		append(namespace.ID{1}, []byte("leaf_2")...),
		append(namespace.ID{3}, []byte("leaf_3")...),
	}
	tree := nmt.New(sha256.New(), nmt.NamespaceIDSize(1))
	for _, leaf := range leaves {
		if err := tree.Push(leaf); err != nil {
			panic(err)
		}
	}

	proof, err := tree.ProveNamespace(namespace.ID{1})
	if err != nil {
		panic(err)
	}

	data, err := json.Marshal(proof)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", data)
	// Output:
	// {"start":2,"end":3,"nodes":["AADq2NJYUYcOTntejk0QCS30laDXOvb+w3Cax5+mM49Xrg==","AwO0onki2V6R1KVmqq3O31AmtiACJxWRCjVBhMCvOE4UQA=="],"is_max_namespace_ignored":true}
}
