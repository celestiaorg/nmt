package namespace

import (
	"bytes"
	"fmt"
)

type IntervalDigest struct {
	min    ID
	max    ID
	digest []byte
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
		min:    digestBytes[:nIDLen],
		max:    digestBytes[nIDLen : 2*nIDLen],
		digest: digestBytes[2*nIDLen:],
	}, nil
}

func (d IntervalDigest) Min() ID {
	return d.min
}

func (d IntervalDigest) Max() ID {
	return d.max
}

func (d IntervalDigest) Hash() []byte {
	return d.digest
}

func (d IntervalDigest) Bytes() []byte {
	return append(append(append(
		make([]byte, 0, len(d.min)*2+len(d.digest)),
		d.min...),
		d.max...),
		d.digest...)
}

func (d *IntervalDigest) Equal(to *IntervalDigest) bool {
	return d.max.Equal(to.max) && d.min.Equal(to.min) && bytes.Equal(d.digest, to.digest)
}

func (d IntervalDigest) String() string {
	return fmt.Sprintf(
		`{
  min: %x
  max: %x
  digest: %x
}`, d.min, d.max, d.digest)
}
