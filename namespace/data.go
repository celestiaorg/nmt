package namespace

type PrefixedData8 []byte

func (d PrefixedData8) NamespaceID() ID {
	return ID(d[:8])
}

func (d PrefixedData8) Data() []byte {
	return d[8:]
}

type PrefixedData struct {
	namespaceLen IDSize
	prefixedData []byte
}

func (n PrefixedData) NamespaceID() ID {
	return n.prefixedData[:n.namespaceLen]
}

func (n PrefixedData) Data() []byte {
	return n.prefixedData[n.namespaceLen:]
}

func NewPrefixedData(namespaceLen IDSize, prefixedData []byte) PrefixedData {
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
