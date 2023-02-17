# Introduction

Namespaced Merkle Tree (NMT) is one of the core components of the Celestia blockchain.
Transactions in Celestia are associated with a namespace ID which signifies the application they belong to.
Nodes interested in a specific application only need to download transactions of a certain namespace ID. 
The Namespaced  Merkle Tree (NMT) was introduced in the [LazyLedger article](https://arxiv.org/abs/1905.09274) to organize transactions in Celestia blocks based on their namespace IDs. 
The NMT allows for efficient and verifiable queries of application-specific transactions by accessing based on the block header which contains the NMT root.
This specification explains the NMT data structure and provides an overview of its current implementation in this repository.

# NMT Data Structure

Namespaced Merkle Tree, at its core, is a normal Merkle tree that employs a modified hash function, namely a [namespaced hash](#namespaced-hash) to ensure each node in the tree encompasses the range of namespaces of its descendants' messages. 
Messages stored in the NMT leaves are all namespace-prefixed with the format `<NsID>||<Message Data>` and arranged in ascending order based on their namespace IDs.
All namespace identifiers have a fixed and known size. 


## Namespaced Hash

NMT utilizes a namespaced hash function i.e., `NsH()`, which in addition to the normal digest calculation, it returns the range of namespace IDs covered by a node's children. The hash output is formatted as  `minNs||maxNs||h(.)`, where `minNs` is the lowest namespace identifier among all the node's descendants, `maxNs` is the highest, and `h(.)` represents the hash digest of `.` (e.g., `SHA256(.)`).

**Leaf Nodes**: Each leaf in the tree represents the namespaced hash of a namespaced message `d = <NsID>||<Message Data>`. 
The hash is computed as follows:

```go
NsH(d) = d.NsID || d.NsID || h(0x00, d)
```
The inclusion of the `0x00` value in the hash calculation serves as a leaf prefix and is done to conform to [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962#section-2.1).

**Non-leaf Nodes**: For an intermediary node `n` of the NMT with children

`r` = `l.minNs || l.maxNs || l.hash` and

`l` = `r.minNs || r.maxNs || r.hash`

the namespaced hash is calculated as

```go
NsH(n) = min(l.minNs, r.minNs) || max(l.maxNs, r.maxNs) || h(0x01, l, r)
```

The inclusion of the `0x01` value in the hash calculation serves as a non-leaf prefix and is done to conform to [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962#section-2.1).

In an NMT data structure, the `minNs` and `maxNs` values of the root node denote the minimum and maximum namespace IDs, respectively, of all messages within the tree.


An example of an NMT is shown in the figure below which utilizes SHA256 as the underlying hash function and namespace ID size of `1` byte. 
The code snippets necessary to create this tree are provided in [NMT Library](#nmt-library) section, and the data items and tree nodes are represented as hex strings. 
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
    00 00 5fa0c9c       00 00 52385a0    01 01 71ca46a       03 03 b4a2792    Leaf Nodes
        |                   |                 |                   |
      NsH()               NsH()              NsH()               NsH()
        |                   |                 |                   |
00 6c6561665f30      00 6c6561665f31    01 6c6561665f32      03 6c6561665f33  Namespaced Data Items 

        0                   1                  2                  3           Leaf Indices
``` 
Figure 1.

## Namespace Proof

NMT supports standard Merkle tree functionalities, including inclusion and range proofs, and offers namespace ID querying and proof generation. 
The following enumerated cases explain potential outcomes when querying an NMT for a namespace ID.

### Namespace Inclusion Proof

When the queried namespace ID `nID` has corresponding items in the tree with root `T`, the query is resolved by a 
namespace inclusion proof which consists of:
1) The starting index `start` and the ending index `end` of the leaves that match `nID`.
2) Nodes of the tree that are necessary for the regular Merkle range proof of `[start, end)` to `T`. 
   In specific, the nodes include 1) the [namespaced hash](#namespaced-hash) of the left siblings for the Merkle 
   inclusion proof of the `start` leaf and 2) the [namespaced hash](#namespaced-hash) of the right siblings of the Merkle inclusion proof of  the `end` leaf. 
   Nodes are sorted according to the in-order traversal of the tree.

For example, the NMT proof of `nID = 0` in Figure 1 would be `[start = 0, end = 2)` and the Merkle inclusion proof embodies one single tree node i.e., `01 03 52c7c03`.

### Namespace Absence Proof

If the namespace ID being queried falls within the range of namespace IDs in the tree root, but there is no corresponding message, an absence proof will be generated. 
An absence proof asserts that no message in the tree matches the queried namespace ID `nID`.

The absence proof consists of:
1) The index of a leaf of the tree that 
   1) its namespace ID is the smallest namespace ID larger than `nID` and
   2) the namespace ID of the leaf to the left of it is smaller than `nID`.
2) A regular Merkle inclusion proof for the said leaf to the tree root `T`.

Note that the proof only requires the hash of the leaf, not its underlying message. 
This is because the aim of the proof is to demonstrate the absence of `nID`.

In Figure 1, if we query for `nID = 2`, we will receive an absence proof since there is no matching item for it. 
The index of the leaf included in the proof will be `3`, which corresponds to the node `03 03 b4a2792`. 
The Merkle inclusion proof for this leaf consists of the following nodes, in the order they appear in an in-order traversal of the tree: `00 00 ead8d25` and `01 01 71ca46a`.


### Namespace Empty Proof
If the requested namespace ID falls outside the namespace range represented by the tree root `T`, the query will be resolved with an empty namespace proof.
In Figure 1, a query for `nID=6` would be responded by an empty proof as it falls outside the root's namsespace range.

## Namespace Proof verification

### Verification of NMT Inclusion Proof

An NMT inclusion proof is deemed valid if it meets the following:
- The namespace ID of the leaves in the returned range `[start, end)` match the queried `nID`.
- **Inclusion**: The supplied Merkle proof for the range `[start, end)` is valid for the given tree root `T`. 
- **Completeness**: There are no other leaves matching `nID` that do not belong to the returned range `[start, end)`.

Proof _inclusion_ can be verified via a regular Merkle range proof verification.
However, _completeness_ of the proof requires additional checks. 
Specifically, 1) the maximum namespace ID of the nodes in the proof that are on the left side of the branch connecting the `start` leaf to the root must be less than the provided namespace ID (`nID`), and 2) the minimum namespace ID of the nodes in the proof that are on the right side of the branch connecting the
 `end-1` leaf to the root must be greater than the provided namespace ID (`nID`).

As an example, the namespace proof for `nID = 0` for the NMT of Figure 1 (which consists of one single node i.e., `01 03 52c7c03`) is complete. This is because the node `01 03 52c7c03` is located on the right side of the branch connecting the leaf at index `end = 1` to the root and its `minNs` value is `01`, which is greater than `nID = 0`.

### Verification of NMT Absence Proof

An NMT absence proof is deemed valid if 
1) The verification of Merkle inclusion proof of the returned leaf is valid.  
2) It satisfies the proof completeness as explained in the [Verification of NMT Inclusion Proof](#verification-of-nmt-inclusion-proof).
Note that hash of the leaf does not have to be verified against the underlying message.

### Verification of Empty NMT proof
If the queried `nID` falls outside the namespace range of the tree root, or the namespace tree is empty, then an empty NMT proof is valid by definition.  


# NMT Library

## NMT Initialization and Configuration

An NMT can be constructed using the `New` function.
```go
func New(h hash.Hash, setters ...Option) *NamespacedMerkleTree
```
It receives a base hash function alongside with some optional configurations, namely:
1. Namespace ID byte-size: If not specified then a default maximum is applied by the library.
2. The initial capacity of the tree i.e., the number of leaves: if not specified, a default maximum is applied.
3. The `IgnoreMaxNamespace` flag. 
By default, the `IgnoreMaxNamespace` flag is set to true, which is a Celestia-specific feature designed to enhance performance when querying namespaces in the NMT. 
This is particularly useful when the NMT is built using data items, of which half are associated with reserved namespace IDs (i.e., the highest possible value within the ID size), that do not need to be queried using their namespace IDs.
For more information on the flag's interpretation, see section [Ignore Max Namespace](#ignore-max-namespace).

A sample configuration of NMT is provided below:

```go
// Init a tree with sha256 as the base hash function
// namespace size of 1 byte
// initial capacity of 4 leaves
// and with the IgnoreMaxNamespace set to true
tree := New(sha256.New(), NamespaceIDSize(1), InitialCapacity(4), IgnoreMaxNamespace(true))
```

One can examine the namespace ID size of the `tree` using

```go
func (n *NamespacedMerkleTree) NamespaceSize() namespace.IDSize
```
E.g.,
```go
idSize := tree.NamespaceSize() // outputs 1
```
### Ignore Max Namespace 
If the NMT is configured with `IgnoreMaxNamespace` set to true, then the calculation of the namespace ID range of non-leaf nodes in the [namespace hash function](#namespaced-hash) will change slightly.
That is, when determining the upper limit of the namespace ID range for a tree node `n`, with children `l` and `r`, the maximum possible namespace ID, equivalent to `NamespaceIDSize()` bytes of `0xFF`, or `2^NamespaceIDSize()-1`,
should be omitted if feasible (in the preceding code example with the ID size of `1` byte, the maximum possible namespace ID would be `0xFF`). 
This is achieved by taking the maximum value among the namespace IDs available in the range of node's left and right children (i.e., `n.maxNs = max(l.minNs, l.maxNs , r.minNs, r.maxNs))`, which is not equal to the maximum possible namespace ID value. 
If such a namespace ID does not exist, the `maxNs` is calculated as normal, i.e., `n.maxNs = max(l.maxNs , r.maxNs)`.

## Add Leaves

Data items are added to the tree using the `Push` method.
Data items should be prefixed with namespaces of size set out for the NMT (i.e.,   `tree.NamespaceSize()`) and added in ascending order of their namespace IDs to avoid errors during the `Push` process. 
Non-compliance with either of these requirements cause `Push` to fail.

```go
func (n *NamespacedMerkleTree) Push(namespacedData namespace.PrefixedData) error
```
E.g.,
```go
d := append(namespace.ID{0}, []byte("leaf_0")...) // the first `tree.NamespaceSize()` bytes of each data item is treated as its namespace ID.
if err := tree.Push(d); err != nil {
	// something went wrong
}
// add a few more data items
d1 := append(namespace.ID{0}, []byte("leaf_1")...) 
if err := tree.Push(d1); err != nil {
    // something went wrong
}
d2 := append(namespace.ID{1}, []byte("leaf_2")...) 
if err := tree.Push(d2); err != nil {
    // something went wrong
}
d3 := append(namespace.ID{3}, []byte("leaf_3")...) 
if err := tree.Push(d3); err != nil {
    // something went wrong
}
```
## Get Root

The `Root()` method calculates the NMT root based on the data that has been added through the use of the `Push` method.
```go
func (n *NamespacedMerkleTree) Root() []byte
```
For example:
```go
// compute the root
root := tree.Root() 
```
In the provided code example, the root would be `00 03 b1c2cc5` (as also illustrated in Figure 1).

The minimum and maximum namespace IDs of the tree root can be obtained through the following methods:

```go
minNS := nmt.MinNamespace(root, tree.NamespaceSize())
maxNS := nmt.MaxNamespace(root, tree.NamespaceSize())
```
 The `minNs` and `maxNs` are equal to `00` and `03` in the supplied example.

## Generate Namespace Proof

The `ProveNamespace` method can be used to generate a namespace proof for a specific namespace ID.

```go
func (n *NamespacedMerkleTree) ProveNamespace(nID namespace.ID) (Proof, error)
```
For example:
```go
nID := namespace.ID{0}
proof, err := tree.ProveNamespace(nID)
if err != nil {
  panic("unexpected error")
}
```

The returned proof is of the following structure:

```go
type Proof struct {
	start int
	end int
	nodes [][]byte
	leafHash []byte
	isMaxNamespaceIDIgnored bool
}
```
The fields can be interpreted as follows:

`start, end`:  They represent the starting index and the ending index of leaves that match the provided namespace ID `nID`. 
Note that `end` is non-inclusive.

`nodes`: The `nodes` hold the tree nodes necessary for the Merkle range proof of `[start, end)`  ordered according to in-order traversal of the tree.
`nodes` embodies an ordered list of byte slices, where each byte slice contains an NMT node. 
Nodes have identical size and all follow the [namespaced hash format](#namespaced-hash).
In the example given earlier, each node is `34` bytes in length and takes the following form:  `minNs<1 byte>||maxNs<1 byte>||h<32 byte>`.

`leafHash`: This field is non-empty only for absence proofs and contains a leaf hash required for such a proof (see [namespace absence proofs](#namespace-absence-proof) section).

`isMaxNamespaceIDIgnored`: If this field is present, then namespace range of the tree nodes are set as explained in the [Ignore Max Namespace](#ignore-max-namespace) section.

## Verify Namespace Proof

The correctness of a namespace `Proof` for a specific namespace ID `nID` can be verified using the [`VerifyNamespace`](https://github.com/celestiaorg/nmt/blob/master/proof.go) method.

```go
func (proof Proof) VerifyNamespace(h hash.Hash, nID namespace.ID, leaves [][]byte, root []byte) bool 
```

- `h` MUST be the same as the underlying hash function used to generate the proof, otherwise, the verification fails.
- `nID` is the namespace ID for which the `proof` is generated.
- `leaves` holds leaves of the NMT in the range of `[proof.start, proof.end)`. 
For an absence `proof`, the `leaves` are empty.
`leaves`  MUST be 1) namespace-prefixed 2) ordered according to their index in the tree, with `leaves[0]` corresponding to the leaf at index `start`, and the last element in leaves corresponding to the leaf at index `end-1`.
- `root` is the root of the NMT against which the `proof` is verified.

E.g.,
```go
leaves := [][]byte{
   append(namespace.ID{0}, []byte("leaf_0")...),
   append(namespace.ID{0}, []byte("leaf_1")...),
}
if proof.VerifyNamespace(sha256.New(), namespace.ID{0}, leaves, root) {
      fmt.Printf("Successfully verified namespace: %x\n", namespace.ID{0})
}
```

## Resources

1. Al-Bassam, Mustafa. "Lazyledger: A distributed data availability ledger with client-side smart contracts." *arXiv preprint arXiv:1905.09274*
 (2019).
2. The outdated specification of NMT https://github.com/celestiaorg/celestia-specs/blob/master/src/specs/data_structures.md#namespace-merkle-tree
3. NMT library  https://github.com/celestiaorg/nmt