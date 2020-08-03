package namespace

type PrefixedData struct {
	namespaceLen uint8
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

func (n PrefixedData) NamespaceSize() uint8 {
	return n.namespaceLen
}

func NewPrefixedData(namespaceLen uint8, prefixedData []byte) PrefixedData {
	return PrefixedData{
		namespaceLen: namespaceLen,
		prefixedData: prefixedData,
	}
}

func PrefixedDataFrom(nID ID, data []byte) PrefixedData {
	return PrefixedData{
		namespaceLen: nID.Size(),
		prefixedData: append(nID, data...),
	}
}
