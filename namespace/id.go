package namespace

import (
	"bytes"
	"math"
)

// IDMaxSize defines the max. allowed namespace ID size in bytes.
const IDMaxSize = math.MaxUint8

// IDSize is the number of bytes a namespace uses.
// Valid values are in [0,255].
type IDSize uint8

// ID represents a namespace ID.
// It's just augments byte slices with a few convenience methods.
type ID []byte

func (nid ID) Less(other ID) bool {
	return bytes.Compare(nid, other) < 0
}

func (nid ID) Equal(other ID) bool {
	return bytes.Equal(nid, other)
}

func (nid ID) LessOrEqual(other ID) bool {
	return bytes.Compare(nid, other) <= 0
}

func (nid ID) Size() IDSize {
	return IDSize(len(nid))
}
func (nid ID) String() string {
	return string(nid)
}
