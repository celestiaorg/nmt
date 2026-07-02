# NMT Proof Format

This document describes the exact format of the proofs produced by this library: what the fields of a proof mean, how the proof nodes are ordered, and how a proof is serialized.
It also shows how to verify a proof using the Go implementation.
For a conceptual explanation of how proofs are generated and verified, see the [NMT specification](./spec/nmt.md) and the [NMT library guide](./nmt-lib.md).

## Proof structure

A [`Proof`](../proof.go) proves the inclusion (or absence) of the leaves in the index range `[start, end)` under an NMT root.
It consists of the following fields:

| Field                     | Type       | Description                                                                                                                                                                |
|---------------------------|------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `start`                   | `int`      | Index of the first leaf covered by the proof (inclusive).                                                                                                                  |
| `end`                     | `int`      | Index one past the last leaf covered by the proof (exclusive).                                                                                                             |
| `nodes`                   | `[][]byte` | The tree nodes needed, together with the leaves in `[start, end)`, to recompute the root. See [ordering of proof nodes](#ordering-of-proof-nodes).                         |
| `leafHash`                | `[]byte`   | Empty for inclusion proofs. For [absence proofs](./spec/nmt.md#namespace-absence-proof), the hash of the leaf occupying the position where the queried namespace would be. |
| `isMaxNamespaceIDIgnored` | `bool`     | Whether the tree was built with the [Ignore Max Namespace](./nmt-lib.md#ignore-max-namespace) option. Celestia sets this to `true`.                                        |

An empty proof (`start = end = 0` and no `nodes`) is returned when the queried namespace falls outside the namespace range of the root (see [namespace empty proof](./spec/nmt.md#namespace-empty-proof)).

### Node format

Every entry of `nodes`, as well as `leafHash` and the root itself, is a **namespaced hash** of the form:

```text
minNs || maxNs || digest
```

where `minNs` and `maxNs` are the minimum and maximum namespace IDs of all the leaves under that node (each of size `NamespaceSize` bytes), and `digest` is the output of the underlying hash function (32 bytes for SHA256).
For example, with SHA256 and Celestia's 29-byte namespaces, every node is `29 + 29 + 32 = 90` bytes.
Leaf and inner digests are domain-separated with a `0x00` or `0x01` prefix, respectively, in accordance with [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962#section-2.1); see the [namespaced hash specification](./spec/nmt.md#namespaced-hash) for the exact hash calculation.

## Ordering of proof nodes

`nodes` contains the roots of the maximal subtrees that do not overlap the proven range `[start, end)` but are needed to recompute the root.
These are the siblings along the paths connecting the proven range to the root:

- the left siblings of the branch connecting the `start` leaf to the root, and
- the right siblings of the branch connecting the `end - 1` leaf to the root.

The nodes are ordered according to an **in-order traversal** of the tree (not preorder or postorder).
Equivalently, they are sorted in ascending order of the leaf indices they cover: the left siblings appear first, in root-to-leaf order, followed by the right siblings in leaf-to-root order.

For example, consider an 8-leaf NMT and a proof for the leaf range `[4, 6)`.
Each internal node below is labeled with the range of leaves it covers:

```text
                 [0,8) (root)
               /        \
          [0,4)          [4,8)
         /      \       /      \
      [0,2)  [2,4)   [4,6)    [6,8)
      /  \    /  \    /  \     /  \
     0    1  2    3  4    5   6    7
```

The proof consists of `nodes = [hash([0,4)), hash([6,8))]`: first the subtree covering leaves 0–3 (the only left sibling), then the subtree covering leaves 6–7 (the only right sibling).
Note that only these maximal subtree roots are included, not the individual leaf hashes underneath them.

As a concrete example, consider the 4-leaf tree of [Figure 1 in the specification](./spec/nmt.md#namespaced-hash), which has leaves with namespaces `0, 0, 1, 3` and a namespace size of 1 byte.
The namespace proof for namespace `1` covers the range `[2, 3)` and contains:

```text
nodes[0] = 00 00 ead8d25...  (root of the subtree covering leaves 0-1, the left sibling)
nodes[1] = 03 03 b4a2792...  (leaf hash of leaf 3, the right sibling)
```

The runnable example `ExampleProof_VerifyNamespace` in [example_test.go](../example_test.go) reproduces exactly this proof.

## Serialization

Proofs are serialized using the [`pb.Proof`](../pb/proof.proto) protobuf message:

```proto
message Proof {
  int64 start = 1;
  int64 end = 2;
  repeated bytes nodes = 3;
  bytes leaf_hash = 4;
  bool is_max_namespace_ignored = 5;
}
```

`Proof` implements `json.Marshaler` and `json.Unmarshaler` by encoding this protobuf message with Go's `encoding/json`. Consequently:

- The JSON keys are `start`, `end`, `nodes`, `leaf_hash`, and `is_max_namespace_ignored`.
- Byte fields (`nodes` entries and `leaf_hash`) are standard base64-encoded strings.
- Zero-valued fields are omitted. For example, `leaf_hash` is absent for inclusion proofs, and `start` is absent when it is `0`.

The namespace proof for namespace `1` from the example above serializes to:

```json
{
  "start": 2,
  "end": 3,
  "nodes": [
    "AADq2NJYUYcOTntejk0QCS30laDXOvb+w3Cax5+mM49Xrg==",
    "AwO0onki2V6R1KVmqq3O31AmtiACJxWRCjVBhMCvOE4UQA=="
  ],
  "is_max_namespace_ignored": true
}
```

## Verifying a proof

### Using this library

The library provides the following verification methods, all defined on `Proof` in [proof.go](../proof.go):

| Method                       | Use it when                                                                                                                                                                                                     |
|------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `VerifyNamespace`            | You have a namespace proof (from `ProveNamespace`) and the complete set of namespace-prefixed leaves for that namespace. Verifies inclusion and completeness, and handles absence and empty proofs.             |
| `VerifyInclusion`            | You have an index-based proof (from `Prove` or `ProveRange`) and the raw leaf data **without** namespace prefixes, all sharing a single namespace. Does not verify completeness.                                |
| `VerifyLeafHashes`           | Like `VerifyInclusion`, but takes leaf hashes instead of raw leaves, and optionally verifies completeness.                                                                                                      |
| `VerifySubtreeRootInclusion` | Celestia-specific: you have subtree roots (per [ADR-013](https://github.com/celestiaorg/celestia-app/blob/main/docs/architecture/adr-013-non-interactive-default-rules-for-zero-padding.md)) instead of leaves. |

For instance, verifying the inclusion of a single raw leaf by index:

```go
tree := nmt.New(sha256.New(), nmt.NamespaceIDSize(1))
// push the namespace-prefixed leaves of Figure 1 and compute the root, then:
proof, err := tree.Prove(2)
if err != nil {
  panic(err)
}
rawLeaves := [][]byte{[]byte("leaf_2")} // leaf data without the namespace prefix
if proof.VerifyInclusion(sha256.New(), namespace.ID{1}, rawLeaves, root) {
  fmt.Println("proof is valid")
}
```

Complete runnable examples are provided in [example_test.go](../example_test.go) and rendered on [pkg.go.dev](https://pkg.go.dev/github.com/celestiaorg/nmt#pkg-examples).

### Reimplementing verification

To verify a proof without this library, recompute the root from the leaf hashes in `[start, end)` and the proof `nodes`, and compare it to the expected root.
The recomputation consumes `nodes` from front to back while recursing through the tree (this mirrors `computeRoot` in [proof.go](../proof.go)):

```text
computeRoot(rangeStart, rangeEnd):
  // if the current subtree does not overlap the proof range, it is covered
  // by the next unconsumed proof node; popFront returns nil if the proof
  // nodes are exhausted, meaning the subtree does not exist in the tree
  if rangeEnd <= proof.start or rangeStart >= proof.end:
    return popFront(proof.nodes)

  // a leaf inside the proof range is the next unconsumed leaf hash
  if rangeEnd - rangeStart == 1:
    return popFront(leafHashes)

  k = largest power of two strictly smaller than (rangeEnd - rangeStart)
  left  = computeRoot(rangeStart, rangeStart + k)
  right = computeRoot(rangeStart + k, rangeEnd)

  // when the number of leaves in the tree is not a power of two, subtrees
  // near the end of the tree may not exist; only the right subtree can be
  // non-existent
  if right is nil:
    return left
  return NsH(0x01, left, right)

size = smallest power of two >= proof.end
root = computeRoot(0, size)
// any remaining proof nodes are roots of subtrees covering leaves at
// indices >= size, ordered from leaf to root
while proof.nodes is not fully consumed:
  root = NsH(0x01, root, popFront(proof.nodes))
```

where `NsH` is the [namespaced hash function](./spec/nmt.md#namespaced-hash) and each leaf hash is computed as `NsH(0x00, namespace || leafData)`.
Namespace proofs additionally require the completeness and absence checks described in [namespace proof verification](./spec/nmt.md#namespace-proof-verification).
