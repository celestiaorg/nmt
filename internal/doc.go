/*
Package internal contains slightly modified versions of these structures from the
NebolousLabs merkletree implementation as well as some internally used abstractions.

The only diff to the NebolousLabs types: They take in a TreeHasher instead of a hash.Hash.

This is an internal package s.t. there types can't be exposed to the publicly visible API.
see: https://dave.cheney.net/2019/10/06/use-internal-packages-to-reduce-your-public-api-surface
*/
package internal
