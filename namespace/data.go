package namespace

// PrefixedData simply represents a slice of bytes which consists of a
// namespace.ID and raw data. The user has to guarantee that the bytes are valid
// namespace prefixed data. Go's type system does not allow enforcing the
// structure we want: [namespaceID, rawData ...], especially as this type does
// not expect any particular size for the namespace.
type PrefixedData []byte
