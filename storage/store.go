package storage

import (
	"github.com/lazyledger/nmt/namespace"
)

const (
	// redefined here to prevent import cycle:
	leafPrefix = 0
)

type NodeStorer interface {
	LeafCache
	Put(key []byte, val []byte)
	Get(key []byte) []byte
	// GetRawLeafHashes is used internally by the the tree.
	// XXX: remove this
	GetRawLeafHashes() [][]byte
}

type LeafCache interface {
	GetLeavesData() namespace.Data
}

var _ NodeStorer = &InMemoryNodeStore{}

type InMemoryNodeStore struct {
	nidSize namespace.IDSize
	nodes   map[string][]byte
	// This is only traverse the nodes in insertion order.
	leafHashes [][]byte
	keys       [][]byte
}

func (i *InMemoryNodeStore) GetLeavesData() namespace.Data {
	panic("TODO implement me")
}

func (i *InMemoryNodeStore) GetRawLeafHashes() [][]byte {
	return i.leafHashes
}

func (i *InMemoryNodeStore) Get(key []byte) []byte {
	return i.nodes[string(key)]
}

func NewInMemoryNodeStore(size namespace.IDSize) *InMemoryNodeStore {
	return &InMemoryNodeStore{
		nidSize: size,
		nodes:   make(map[string][]byte),
		keys:    make([][]byte, 0),
	}
}

func (i *InMemoryNodeStore) Put(key, val []byte) {
	_, present := i.nodes[string(key)]
	i.nodes[string(key)] = val
	if !present {
		if i.isLeaf(val) {
			i.leafHashes = append(i.leafHashes, key)
		} else {
			i.keys = append(i.keys, key)
		}
	}
}

func (i *InMemoryNodeStore) isLeaf(val []byte) bool {
	if len(val) == 0 { // base case
		return true
	}
	rawData := val
	return rawData[0] == leafPrefix

}

func (i InMemoryNodeStore) Count() int {
	return len(i.nodes)
}
