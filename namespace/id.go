package namespace

import "bytes"

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

func (nid ID) Size() uint8 {
	return uint8(len(nid))
}
