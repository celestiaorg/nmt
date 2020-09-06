package namespace

// Data represent namespaced data.
// Anything that implements this interface can be pushed
// into an NMT.
type Data interface {
	// NamespaceID returns the underlying namespace.ID
	// associated with this Data.
	NamespaceID() ID
	// Data returns the data as bytes (without the namespace)
	Data() []byte
}

type PrefixedData32 []byte

func (d PrefixedData32) NamespaceID() ID {
	return ID(d[:32])
}

func (d PrefixedData32) Data() []byte {
	return d[32:]
}

func (d PrefixedData32) NamespaceSize() uint8 {
	return 32
}

type PrefixedData16 []byte

func (d PrefixedData16) NamespaceID() ID {
	return ID(d[:16])
}

func (d PrefixedData16) Data() []byte {
	return d[16:]
}

func (d PrefixedData16) NamespaceSize() uint8 {
	return 16
}

type PrefixedData8 []byte

func (d PrefixedData8) NamespaceID() ID {
	return ID(d[:8])
}

func (d PrefixedData8) Data() []byte {
	return d[8:]
}

func (d PrefixedData8) NamespaceSize() uint8 {
	return 8
}

type PrefixedData struct {
	namespaceLen Size
	prefixedData []byte
}

func (n PrefixedData) NamespaceID() ID {
	return n.prefixedData[:n.namespaceLen]
}

func (n PrefixedData) Data() []byte {
	return n.prefixedData[n.namespaceLen:]
}

func NewPrefixedData(namespaceLen Size, prefixedData []byte) PrefixedData {
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
