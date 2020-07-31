package types

import "bytes"

type NamespaceID []byte

func (nid NamespaceID) Less(other NamespaceID) bool {
	return bytes.Compare(nid, other) < 0
}

func (nid NamespaceID) Equal(other NamespaceID) bool {
	return bytes.Equal(nid, other)
}
