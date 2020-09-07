/*
Package internal contains slightly modified versions of these structures from the
NebolousLabs merkletree implementation as well as some internally used abstractions.

The only diff to the NebolousLabs types: They take in a TreeHasher instead of a hash.Hash.
TODO: this should probably live in our fork which currently lives under
"github.com/liamsi/merkletree" and should be moved to the LL org.
see: https://github.com/lazyledger/nmt/pull/3#discussion_r461415836

This is an internal package s.t. there types can't be exposed to the publicly visible API.
see: https://dave.cheney.net/2019/10/06/use-internal-packages-to-reduce-your-public-api-surface
*/
package internal
