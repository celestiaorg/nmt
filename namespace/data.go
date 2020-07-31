package namespace

type PrefixedData struct {
	namespaceLen int
	prefixedData []byte
}

func (n PrefixedData) NamespaceID() ID {
	return n.prefixedData[:n.namespaceLen]
}

func (n PrefixedData) Data() []byte {
	return n.prefixedData[n.namespaceLen:]
}

func (n PrefixedData) Bytes() []byte {
	return n.prefixedData
}

func (n PrefixedData) NamespaceSize() int {
	return n.namespaceLen
}

func NewPrefixedData(namespaceLen int, prefixedData []byte) *PrefixedData {
	return &PrefixedData{
		namespaceLen: namespaceLen,
		prefixedData: prefixedData,
	}
}

func PrefixedDataFrom(namespace []byte, data []byte) *PrefixedData {
	return &PrefixedData{
		namespaceLen: len(namespace),
		prefixedData: append(namespace, data...),
	}
}
