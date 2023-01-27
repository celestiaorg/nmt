package namespace

// PrefixedData simply represents a slice of bytes which consists of
// a namespace.ID and raw data.
// The user has to guarantee that the bytes are valid namespace prefixed data.
// Go's type system does not allow enforcing the structure we want:
// [namespaceID, rawData ...], especially as this type does not expect any
// particular size for the namespace.
// TODO [Me] Shouldn't we specify that the first 8 bytes represent the namespace.ID
type PrefixedData []byte

// PrefixedData8 like PrefixedData is just a slice of bytes.
// It assumes that the slice it represents is at least 8 bytes.
// This assumption is not enforced by the type system though.
type PrefixedData8 []byte

func (d PrefixedData8) NamespaceID() ID {
	return ID(d[:8])
}

func (d PrefixedData8) Data() []byte {
	return d[8:]
}
