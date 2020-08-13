package namespace

// Data represent namespaced data.
// Anything that implements this interface can be pushed
// into an NMT.
type Data interface {
	NamespaceID() ID
	Data() []byte
	MarshalBinary() ([]byte, error)
	NamespaceSize() uint8
}

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

func (n PrefixedData) MarshalBinary() ([]byte, error) {
	return n.prefixedData, nil
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
