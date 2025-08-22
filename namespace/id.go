package namespace

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
)

type ID []byte

// Less returns true if nid < other, otherwise, false.
func (nid ID) Less(other ID) bool {
	// Fast path for common 8-byte namespace size
	if len(nid) == 8 && len(other) == 8 {
		return lessUint64(nid, other)
	}
	return bytes.Compare(nid, other) < 0
}

// lessUint64 compares two 8-byte slices as big-endian uint64s
func lessUint64(a, b []byte) bool {
	aVal := binary.BigEndian.Uint64(a)
	bVal := binary.BigEndian.Uint64(b)
	return aVal < bVal
}

// Equal returns true if nid == other, otherwise, false.
func (nid ID) Equal(other ID) bool {
	return bytes.Equal(nid, other)
}

// LessOrEqual returns true if nid <= other, otherwise, false.
func (nid ID) LessOrEqual(other ID) bool {
	return bytes.Compare(nid, other) <= 0
}

// Size returns the byte size of the nid.
func (nid ID) Size() IDSize {
	return IDSize(len(nid))
}

// String returns the hexadecimal encoding of the nid. The output of
// nid.String() is not equivalent to string(nid).
func (nid ID) String() string {
	return hex.EncodeToString(nid)
}
