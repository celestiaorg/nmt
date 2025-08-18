# Namespace Merkle Tree Library

The Namespace Merkle Tree (NMT) library implements the NMT data structure outlined in the [NMT spec](./spec/nmt.md).
In the following sections, we will provide instructions on how to utilize the library to construct an NMT and offer insights into its fundamental methods.

## NMT Initialization and Configuration

An NMT can be constructed using the `New` function.

```go
func New(h hash.Hash, setters ...Option) *NamespacedMerkleTree
```

It receives a base hash function alongside some optional configurations, namely:

1. Namespace ID byte-size: If not specified then a default is applied by the library.
2. The initial capacity of the tree i.e., the number of leaves: if not specified, a default is applied.
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

If the NMT is configured with `IgnoreMaxNamespace` set to true (the flag is explained [here](#nmt-initialization-and-configuration)), then the calculation of the namespace ID range of non-leaf nodes in the [namespace hash function](./spec/nmt.md#namespaced-hash) will change slightly.
That is, if the right child of a node is entirely filled with leaves with the maximum possible namespace `maxPossibleNamespace`, i.e., its minimum and maximum namespace are equal to the `maxPossibleNamespace`, then the right child is excluded from the calculation of the namespace ID range of the parent node, and the parent node inherits the namespace range of the left child.
In the preceding code example with the ID size of `1` byte, the value of `maxPossibleNamespace` is $2^8-1 = 0xFF$.
Concretely, consider a node `n` with children `l` and `r`. If `r.minNs` and `r.maxNs` are both equal to `maxPossibleNamespace` (indicating that it represents the root of a subtree whose leaves all have the namespace ID of `maxPossibleNamespace`), then the namespace ID range of `n` is set to the namespace range of `l`, i.e., `n.MinNs = l.MinNs` and `n.MaxNs = l.MaxNs`.
Otherwise, the namespace ID range of `n` is set as normal i.e., `n.minNs = min(l.minNs, r.minNs)` and `n.maxNs = max(l.maxNs, r.maxNs)`.

Note that the `IgnoreMaxNamespace` flag is Celestia-specific and is motivated by the fact that half of the data items in the NMT are associated with reserved namespace IDs (i.e., the highest possible value within the ID size) and do not need to be queried using their namespace IDs.

[//]: # (Precisely, if a set `C` $= \bigl \lbrace$ `ns` $\in \lbrace$`l.minNs`, `l.maxNs`, `r.minNs`, `r.maxNs` $\rbrace:$ `ns` $<$ `maxPossibleNamespace` $\bigr \rbrace$ is not empty, `n.maxNs = max&#40;C&#41;`. If `C` is empty, `n.maxNs = maxPossibleNamespace`.)

## Add Leaves

Data items are added to the tree using the `Push` method.
Data items should be prefixed with namespaces of size set out for the NMT (i.e., `tree.NamespaceSize()`) and added in ascending order of their namespace IDs to avoid errors during the `Push` process.
Non-compliance with either of these requirements cause `Push` to fail.

```go
func (n *NamespacedMerkleTree) Push(namespacedData namespace.PrefixedData) error
```

E.g.,

```go
d := namespace.PrefixedData(append(namespace.ID{0}, []byte("leaf_0")...)) // the first `tree.NamespaceSize()` bytes of each data item is treated as its namespace.
if err := tree.Push(d); err != nil {
// something went wrong
}
// add a few more data items
d1 := namespace.PrefixedData(append(namespace.ID{0}, []byte("leaf_1")...))
if err := tree.Push(d1); err != nil {
// something went wrong
}
d2 := namespace.PrefixedData(append(namespace.ID{1}, []byte("leaf_2")...))
if err := tree.Push(d2); err != nil {
// something went wrong
}
d3 := namespace.PrefixedData(append(namespace.ID{3}, []byte("leaf_3")...))
if err := tree.Push(d3); err != nil {
// something went wrong
}
```

The above code snippets generate the NMT illustrated in Figure 1.
The tree employs SHA256 as its underlying hash function and a namespace ID size of `1` byte.
Both data items and tree nodes are represented as hexadecimal strings.
To keep the diagram concise, we have only included the first seven digits of each namespace hash's SHA256 value.

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

## Get Root

The `Root()` method calculates the NMT root based on the data that has been added through the use of the `Push` method.
The root value is valid if the method does not return an error.

```go
func (n *NamespacedMerkleTree) Root() ([]byte, error)
```

For example:

```go
// compute the root
root, err := tree.Root()
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
Nodes have identical size and all follow the [namespaced hash format](./spec/nmt.md#namespaced-hash).
In the example given earlier, each node is `34` bytes in length and takes the following form:  `minNs<1 byte>||maxNs<1 byte>||h<32 byte>`.

`leafHash`: This field is non-empty only for absence proofs and contains a leaf hash required for such a proof (see [namespace absence proofs](./spec/nmt.md#namespace-absence-proof) section).

`isMaxNamespaceIDIgnored`: If this field is true, then namespace range of the tree nodes are set as explained in the [Ignore Max Namespace](#ignore-max-namespace) section.

## Verify Namespace Proof

The correctness of a namespace `Proof` for a specific namespace ID `nID` can be verified using the [`VerifyNamespace`](https://github.com/celestiaorg/nmt/blob/main/proof.go) method.

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
