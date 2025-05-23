# Namespaced Merkle Tree (NMT)

[![Go Reference](https://pkg.go.dev/badge/github.com/celestiaorg/nmt.svg)](https://pkg.go.dev/github.com/celestiaorg/nmt)
![golangci-lint](https://github.com/celestiaorg/nmt/workflows/lint/badge.svg)<!-- it retrieves the lint workflow status badge for the default branch i.e., main, for a different branch, specify the branch parameter in the URL() -->
![Go](https://github.com/celestiaorg/nmt/workflows/Go/badge.svg)

A Namespaced Merkle Tree is
> [...] an ordered Merkle tree that uses a modified hash function
  so that each node in the tree includes the range of
  namespaces of the messages in all of the descendants
  of each node. The leafs in the tree are ordered by the
  namespace identifiers of the messages.
  In a namespaced Merkle tree, each non-leaf node in
  the tree contains the lowest and highest namespace
  identifiers found in all the leaf nodes that are descendants of the non-leaf node, in addition to the hash of
  the concatenation of the children of the node. This
  enables Merkle inclusion proofs to be created that prove to a verifier that all the elements of the tree for
  a specific namespace have been included in a Merkle
  inclusion proof.

The concept was first introduced by [@musalbas] in the LazyLedger [academic paper].

## Example

```go
package main

import (
    "bytes"
    "crypto/sha256"
    "fmt"

    "github.com/celestiaorg/nmt"
    "github.com/celestiaorg/nmt/namespace"
)

func main() {
    // the tree will use this namespace size (number of bytes)
    nidSize := 1
    // the leaves that will be pushed
    data := [][]byte{
      append(namespace.ID{0}, []byte("leaf_0")...),
      append(namespace.ID{0}, []byte("leaf_1")...),
      append(namespace.ID{1}, []byte("leaf_2")...),
      append(namespace.ID{1}, []byte("leaf_3")...)}
    // Init a tree with the namespace size as well as
    // the underlying hash function:
    tree := nmt.New(sha256.New(), nmt.NamespaceIDSize(nidSize))
    for _, d := range data {
      if err := tree.Push(d); err != nil {
        panic(fmt.Sprintf("unexpected error: %v", err))
      }
    }
    // compute the root
    root, err := tree.Root()
    if err != nil {
      panic(fmt.Sprintf("unexpected error: %v", err))
    }
    // the root's min/max namespace is the min and max namespace of all leaves:
    minNS := nmt.MinNamespace(root, tree.NamespaceSize())
    maxNS := nmt.MaxNamespace(root, tree.NamespaceSize())
    if bytes.Equal(minNS, namespace.ID{0}) {
      fmt.Printf("Min namespace: %x\n", minNS)
    }
    if bytes.Equal(maxNS, namespace.ID{1}) {
      fmt.Printf("Max namespace: %x\n", maxNS)
    }

    // compute proof for namespace 0:
    proof, err := tree.ProveNamespace(namespace.ID{0})
    if err != nil {
      panic("unexpected error")
    }

    // verify proof using the root and the leaves of namespace 0:
    leafs := [][]byte{
      append(namespace.ID{0}, []byte("leaf_0")...),
      append(namespace.ID{0}, []byte("leaf_1")...),
    }

    if proof.VerifyNamespace(sha256.New(), namespace.ID{0}, leafs, root) {
      fmt.Printf("Successfully verified namespace: %x\n", namespace.ID{0})
    }

    if proof.VerifyNamespace(sha256.New(), namespace.ID{2}, leafs, root) {
      panic(fmt.Sprintf("Proof for namespace %x, passed for namespace: %x\n", namespace.ID{0}, namespace.ID{2}))
    }
}
```

The above will create a Namespaced merkle tree with four leafs which looks like this:

![example](imgs/example_4-leaves.png)

Where `nid_0 = nid_1 = 0` and `nid_2 = nid_3 = 1` and `data_i = "leaf_i"` for `i = 0,...,3`.

## Related

This implementation was heavily inspired by the initial implementation in [celestiaorg/lazyledger-prototype](https://github.com/celestiaorg/lazyledger-prototype).

Non-endorsed implementations of NMT exist in other languages:

Language | Repo
---------|------------------------------------------------------------------
Rust     | [Sovereign-Labs/nmt-rs](https://github.com/Sovereign-Labs/nmt-rs)

<!--- TODO references --->
[academic paper]: https://arxiv.org/abs/1905.09274
[@musalbas]: https://github.com/musalbas

## Contributing

Markdown files must conform to [GitHub Flavored Markdown](https://github.github.com/gfm/). Markdown must be formatted with:

- [markdownlint](https://github.com/DavidAnson/markdownlint)
- [Markdown Table Prettifier](https://github.com/darkriszty/MarkdownTablePrettify-VSCodeExt)

## Audits

Date      | Auditor                                       | Report
----------|-----------------------------------------------|--------------------------------------------------------
2023/8/18 | [Informal Systems](https://informal.systems/) | [informal-systems.pdf](docs/audit/informal-systems.pdf)
