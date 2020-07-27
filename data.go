package nmt

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
