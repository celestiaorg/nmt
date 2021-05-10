package namespace

import (
	"bytes"
	"fmt"
)

type IntervalDigest struct {
	Min    ID     `json:"min"`
	Max    ID     `json:"max"`
	Digest []byte `json:"digest"`
}

// IntervalDigestFromBytes is the inverse function to IntervalDigest.Bytes().
// In other words, it assumes that the passed in digestBytes are of the form
// d.Min() || d.Max() || d.Hash() for an IntervalDigest d.
func IntervalDigestFromBytes(nIDLen IDSize, digestBytes []byte) (IntervalDigest, error) {
	if len(digestBytes) < int(2*nIDLen) {
		return IntervalDigest{}, fmt.Errorf("invalid digest: %x, expected length >= %v, got: %v",
			digestBytes, 2*nIDLen, len(digestBytes))
	}

	return IntervalDigest{
		Min:    digestBytes[:nIDLen],
		Max:    digestBytes[nIDLen : 2*nIDLen],
		Digest: digestBytes[2*nIDLen:],
	}, nil
}

func (d IntervalDigest) Hash() []byte {
	return d.Digest
}

func (d IntervalDigest) Bytes() []byte {
	return append(append(append(
		make([]byte, 0, len(d.Min)*2+len(d.Digest)),
		d.Min...),
		d.Max...),
		d.Digest...)
}

func (d *IntervalDigest) Equal(to *IntervalDigest) bool {
	return d.Max.Equal(to.Max) && d.Min.Equal(to.Min) && bytes.Equal(d.Digest, to.Digest)
}

func (d IntervalDigest) String() string {
	return fmt.Sprintf(
		`{
  min: %x
  max: %x
  digest: %x
}`, d.Min, d.Max, d.Digest)
}
