package nmt

import "bytes"

type NamespaceID []byte

func (nid NamespaceID) Less(other NamespaceID) bool {
	return bytes.Compare(nid, other) < 0
}

func (nid NamespaceID) Equal(other NamespaceID) bool {
	return bytes.Equal(nid, other)
}

type NamespacePrefixedData struct {
	namespaceLen int
	prefixedData []byte
}

func (n NamespacePrefixedData) NamespaceID() NamespaceID {
	return n.prefixedData[:n.namespaceLen]
}

func (n NamespacePrefixedData) Data() []byte {
	return n.prefixedData[n.namespaceLen:]
}

func (n NamespacePrefixedData) Bytes() []byte {
	return n.prefixedData
}

func (n NamespacePrefixedData) NamespaceSize() int {
	return n.namespaceLen
}

func FromPrefixedData(namespaceLen int, prefixedData []byte) *NamespacePrefixedData {
	return &NamespacePrefixedData{
		namespaceLen: namespaceLen,
		prefixedData: prefixedData,
	}
}

func FromNamespaceAndData(namespace []byte, data []byte) *NamespacePrefixedData {
	return &NamespacePrefixedData{
		namespaceLen: len(namespace),
		prefixedData: append(namespace, data...),
	}
}
