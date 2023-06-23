# Namespaced Merkle Tree

## Abstract

Namespaced Merkle Tree (NMT) is one of the core components of the Celestia blockchain.
Transactions in Celestia are associated with a namespace ID which signifies the application they belong to.
Nodes interested in a specific application only need to download transactions of a certain namespace ID.
The Namespaced  Merkle Tree (NMT) was introduced in the [LazyLedger article](https://arxiv.org/abs/1905.09274) to organize transactions in Celestia blocks based on their namespace IDs.
The NMT allows for efficient and verifiable queries of application-specific transactions by accessing based on the block header which contains the NMT root.
This specification explains the NMT data structure and provides an overview of its current implementation in this repository.
The NMT library, which is the implementaion of NMT data structure, is explained in the [NMT Library](./../nmt-lib.md) document.

## NMT Data Structure

Namespaced Merkle Tree, at its core, is a normal Merkle tree that employs a modified hash function, namely a [namespaced hash](#namespaced-hash) to ensure each node in the tree encompasses the range of namespaces of its descendants' messages.
Messages stored in the NMT leaves are all namespace-prefixed with the format `<NsID>||<Message Data>` and arranged in ascending order based on their namespace IDs.
All namespace identifiers have a fixed and known size.

### Namespaced Hash

NMT utilizes a namespaced hash function i.e., `NsH()`, which in addition to the normal digest calculation, it returns the range of namespace IDs covered by a node's children. The hash output is formatted as  `minNs||maxNs||h(.)`, where `minNs` is the lowest namespace identifier among all the node's descendants, `maxNs` is the highest, and `h(.)` represents the hash digest of `.` (e.g., `SHA256(.)`).

**Leaf Nodes**: Each leaf in the tree represents the namespaced hash of a namespaced message `d = <NsID>||<Message Data>`.
The hash is computed as follows:

```go
NsH(d) = d.NsID || d.NsID || h(0x00, d)
```

The inclusion of the `0x00` value in the hash calculation serves as a leaf prefix and is done to conform to [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962#section-2.1).

**Non-leaf Nodes**: For an intermediary node `n` of the NMT with children

`l` = `l.minNs || l.maxNs || l.hash` and

`r` = `r.minNs || r.maxNs || r.hash`

the namespaced hash is calculated as

```go
NsH(n) = min(l.minNs, r.minNs) || max(l.maxNs, r.maxNs) || h(0x01, l, r)
```

The inclusion of the `0x01` value in the hash calculation serves as a non-leaf prefix and is done to conform to [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962#section-2.1).

In an NMT data structure, the `minNs` and `maxNs` values of the root node denote the minimum and maximum namespace IDs, respectively, of all messages within the tree.

An example of an NMT is shown in the figure below which utilizes SHA256 as the underlying hash function and namespace ID size of `1` byte.
The code snippets necessary to create this tree are provided in [NMT Library](./../nmt-lib.md) documentation, and the data items and tree nodes are represented as hex strings.
For the sake of brevity, we have only included the first 7 hex digits of SHA256 for each namespace hash.

```markdown
                                 00 03 b1c2cc5                                Tree Root
                           /                       \
                          /                         \
                        NsH()                       NsH()
                        /                             \
                       /                               \
               00 00 ead8d25                      01 03 52c7c03               Non-Leaf Nodes
              /            \                    /               \
            NsH()          NsH()              NsH()             NsH()
            /                \                /                   \
    00 00 5fa0c9c       00 00 52385a0    01 01 71ca46a       03 03 b4a2792    Leaf Hashes
        |                   |                 |                   |
      NsH()               NsH()              NsH()               NsH()
        |                   |                 |                   |
00 6c6561665f30      00 6c6561665f31    01 6c6561665f32      03 6c6561665f33  Leaves with namespace IDs

        0                   1                  2                  3           Leaf Indices
```

Figure 1.

### Namespace Proof

NMT supports standard Merkle tree functionalities, including inclusion and range proofs, and offers namespace ID querying and proof generation.
The following enumerated cases explain potential outcomes when querying an NMT for a namespace ID.

#### Namespace Inclusion Proof

When the queried namespace ID `NS` has corresponding items in the tree with root `T`, the query is resolved by a
namespace inclusion proof which consists of:

1) The starting index `start` and the ending index `end` of the leaves that match `NS`.
2) Nodes of the tree that are necessary for the regular Merkle range proof of `[start, end)` to `T`.
   In specific, the nodes include 1) the [namespaced hash](#namespaced-hash) of the left siblings for the Merkle
   inclusion proof of the `start` leaf and 2) the [namespaced hash](#namespaced-hash) of the right siblings of the Merkle inclusion proof of the `end-1` leaf.
   Nodes are sorted according to the in-order traversal of the tree.

For example, the NMT proof of `NS = 0` in Figure 1 would be `[start = 0, end = 2)` and the Merkle inclusion proof embodies one single tree node i.e., `01 03 52c7c03`.

#### Namespace Absence Proof

If the namespace being queried falls within the range of namespaces in the tree root, but there is no corresponding message, an absence proof will be generated.
An absence proof asserts that no message in the tree matches the queried namespace `NS`.

The absence proof consists of:

1) The index of a leaf of the tree that
   1) its namespace is the smallest namespace larger than `NS` and
   2) the namespace of the leaf to the left of it is smaller than `NS`.
2) A regular Merkle inclusion proof for the said leaf to the tree root `T`.
3) The hash of the said leaf denoted by `LeafHash`.

Note that the proof only requires the hash of the leaf, not its underlying message.
This is because the aim of the proof is to demonstrate the absence of `NS`.

In Figure 1, if we query for `NS = 2`, we will receive an absence proof since there is no matching item for it.
The index of the leaf included in the proof will be `3`, which corresponds to the node `03 03 b4a2792`.
The Merkle inclusion proof for this leaf consists of the following nodes, in the order they appear in an in-order traversal of the tree: `00 00 ead8d25` and `01 01 71ca46a`.

#### Namespace Empty Proof

If the requested namespace falls outside the namespace range represented by the tree root `T`, the query will be resolved with an empty namespace proof.
In Figure 1, a query for `NS=6` would be responded by an empty proof as it falls outside the root's namsespace range.

### Namespace Proof verification

#### Verification of NMT Inclusion Proof

An NMT inclusion proof is deemed valid if it meets the following:

- The namespace of the leaves in the returned range `[start, end)` match the queried `NS`.
- **Inclusion**: The supplied Merkle proof for the range `[start, end)` is valid for the given tree root `T`.
- **Completeness**: There are no other leaves matching `NS` that do not belong to the returned range `[start, end)`.

Proof _inclusion_ can be verified via a regular Merkle range proof verification.
However, _completeness_ of the proof requires additional checks.
Specifically, 1) the maximum namespace of the nodes in the proof that are on the left side of the branch connecting the `start` leaf to the root must be less than the provided namespace (`NS`), and 2) the minimum namespace of the nodes in the proof that are on the right side of the branch connecting the
 `end-1` leaf to the root must be greater than the provided namespace (`NS`).

As an example, the namespace proof for `NS = 0` for the NMT of Figure 1 (which consists of one single node i.e., `01 03 52c7c03`) is complete. This is because the node `01 03 52c7c03` is located on the right side of the branch connecting the leaf at index `end = 1` to the root and its `minNs` value is `01`, which is greater than `NS = 0`.

#### Verification of NMT Absence Proof

An NMT absence proof is deemed valid if it meets the following:

1) The minimum namespace of the leaf in the proof is greater than the queried `NS`.
2) The verification of Merkle inclusion proof of the returned leaf is valid.
3) It satisfies the proof completeness as explained in the [Verification of NMT Inclusion Proof](#verification-of-nmt-inclusion-proof).
Note that hash of the leaf does not have to be verified against the underlying message.

#### Verification of Empty NMT proof

If the queried `NS` falls outside the namespace range of the tree root, or the namespace tree is empty, then an empty NMT proof is valid by definition.

### Index-based Merkle Range Proof

NMTs also support regular index-based Merkle Proof that allows for both Merkle inclusion proof for a single leaf index and Merkle range proof for a range of leaf indices `[start, end)`,
where `end` is greater than `start`.
The Merkle inclusion proof for a single leaf is actually a special case of the Merkle range proof where the range represents a single leaf index, or in other words, when `end` is equal to `start+1`.
As such, we only focus on the Merkle range proof in this section.
The `start` and `end` are zero-based indices of the leaves in the tree, where `start` is inclusive and `end` is exclusive.
The `start` ranges from `0` to `n-1`, where `n` is the number of leaves in the tree, while end ranges from `1` to `n`.

#### Index-based Merkle Range Proof Generation (for leaves with identical namespaces)

A range query for a range of `[start, end)` is answered by a `proof` consisting of two pieces of data: `nodes` and `start`/`end`.
The proof generation and verification logic explained here is based on the assumption that all the leaves within the queried range have the same namespace.
The assumption is to conform to the current implementation of the [NMT library](https://github.com/celestiaorg/nmt), however, it is not a limitation imposed by the NMT data structure.

- The `nodes` data is a set of tree nodes that constitutes the Merkle range proof of `[start, end)` to the tree with root T.
This includes the left siblings of the nodes along the branch connecting the `start` leaf to the NMT root and the right siblings of the nodes along the branch connecting the `end-1` leaf to the root.
The nodes are sorted based on the in-order traversal of the tree.
- The `start` and `end` data represent the starting and ending index of the retrieved leaves, respectively, where `end` is non-inclusive.
This is the same as the queried range.

- In the event that the queried range is outside the range of the NMT leaves indices, an empty `proof` is returned.
This empty `proof` consists of an empty set of `nodes` and an empty range, where `start` is `0` and `end` is also `0`.

#### Index-based Merkle Range Proof Verification (for leaves with identical namespaces)

Let `leaves` refer to the namespaced messages of the leaves in the queried range `[start, end)`, while `T` represents the root of the tree against which the `proof` is being verified.
The `proof` can be verified by taking the following steps:

- Verify that all the leaves are namespaced messages with the same namespace.
- Compute the tree root `T'` using the leaves and the `proof.nodes`.
If the computed root `T'` is equal to the expected root `T` of the tree, then the `proof` is valid.
To compute the tree root `T'`, the [namespaced hash function](#namespaced-hash) should be utilized.

### Short Namespace Absence Proof

The short namespace absence proof is a more efficient variant of the regular namespace absence proof.
It differs from the original namespace absence proof definition  where instead of providing the inclusion proof of the `LeafHash` to the root (as `proof.nodes`),
a short absence proof supplies the Merkle inclusion proof of one of the predecessors of the `LeafHash`.
This predecessor is located along the branch connecting the `LeafHash` to the root.
Importantly, the namespace range of this predecessor does not overlap with the queried namespace i.e., the absent namespace.
As this predecessor is located closer to the root compared to the `LeafHash`, it will have shorter Merkle inclusion proof i.e., lower number of  elements in the  `proof.nodes`.

At present, the NMT library does not support the generation of short namespace absence proofs.
However, it is capable of correctly verifying such proofs.

#### Short Namespace Absence Proof Generation

More formally, the short namespace absence proof consists of the following components:

1) `SubtreeHash`: To compute the `SubtreeHash`, the following steps should be followed:
   1) Find the index of a leaf in the tree that meets two conditions:
      1) Its namespace is the smallest ID greater than `NS`.
      1) The namespace of the leaf to its left is smaller than `NS`.
   1) Traverse up the branch connecting that leaf to the root and locate one of the parents/grandparents of that leaf whose namespace range does not overlap with the queried namespace. 
   The `SubtreeHash` is the hash of that node.
1) `start` and `end` range: These represent the indices of the `SubtreeHash` within its respective level. 
Nodes at each level are indexed from left to right starting at index `0`.
1) `nodes`: This set comprises the index-based  Merkle inclusion proof of the `SubtreeHash` to the tree root `T`.

Below, we illustrate the short namespace absence proof for namespace `NS = 02` in an 8-leaf tree:
The namespace `03` is the smallest namespace larger than `02`. 
By traversing the branch from the leaf with namespace `03` to the root, we find a node with hash `03 04 52c7c03` whose namespace range doesn't overlap with `02`. 
This node is the highest such node along the branch.
The `SubtreeHash` is the hash of that node, which is `03 04 52c7c03`.
The `start` and `end` indices indicate its position in the respective level. 
In this case, `start = 1` and `end = 2`. 
Note that node indices start at `0` from left to right at each level.
The `nodes` form the index-based Merkle inclusion proof of the `SubtreeHash` to the tree root `T`. 
The `nodes` set includes `00 00 ead8d25`, the left sibling of `03 04 52c7c03`.

In summary, the short namespace absence proof for `NS = 02` in this tree consists of `SubtreeHash = 03 04 52c7c03`, `start = 1`, `end = 2`, and the `nodes` set containing `00 00 ead8d25`.

```markdown
                                 00 04 b1c2cc5                                Tree Root
                           /                       \
                          /                         \
                        NsH()                       NsH()
                        /                             \
                       /                               \
                      /                           -------------
               00 00 ead8d25                     |03 04 52c7c03|              Non-Leaf Nodes
                /         \                       -------------
              /            \                    /               \
            NsH()          NsH()              NsH()             NsH()
            /                \                /                   \
    00 00 5fa0c9c       00 00 52385a0    03 03 71ca46a       04 04 b4a2792    Leaf Hashes
        |                   |                 |                   |
      NsH()               NsH()              NsH()               NsH()
        |                   |                 |                   |
00 6c6561665f30      00 6c6561665f31    03 6c6561665f32      04 6c6561665f33  Leaves with namespaces

        0                   1                  2                  3           Leaf Indices
```

#### Short Namespace Absence Proof Verification

A short namespace absence proof is deemed valid if it meets the following:

1) The minimum namespace of the `SubtreeHash` in the `proof` is greater than the queried `NS`.
It is important to note that there can be multiple candidates, each belonging to a different level of the tree, that satisfy this requirement for the `SubtreeHash`.
All such candidates are deemed valid from the verification perspective.
2) The verification of Merkle inclusion proof of the returned `SubtreeHash` is valid.
3) The `proof` satisfies the proof completeness as explained in the [Verification of NMT Inclusion Proof](#verification-of-nmt-inclusion-proof).
That is, all nodes on the left side of the branch connecting `SubtreeHash` to the root `T` have a maximum namespace less than the queried `NS`.
Conversely, all nodes on the right side are expected to have a minimum namespace larger than `NS`.

## Resources

1. Al-Bassam, Mustafa. "Lazyledger: A distributed data availability ledger with client-side smart contracts." _arXiv preprint arXiv:1905.09274_
 (2019).
2. The outdated specification of NMT <https://github.com/celestiaorg/celestia-specs/blob/master/src/specs/data_structures.md#namespace-merkle-tree>
3. NMT library  <https://github.com/celestiaorg/nmt>
