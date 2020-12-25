package namespace

import "fmt"

type IntervalDigest struct {
	min    ID
	max    ID
	digest []byte
}

// IntervalDigestFromBytes is the inverse function to IntervalDigest.Bytes().
// In other words, it assumes that the passed in digestBytes are of the form
// d.Min() || d.Max() || d.Hash() for an IntervalDigest d.
func IntervalDigestFromBytes(nIDLen IDSize, digestBytes []byte) IntervalDigest {
	if len(digestBytes) < int(2*nIDLen) {
		panic(fmt.Sprintf("invalid digest: %x, expected length >= %v, got: %v",
			digestBytes, 2*nIDLen, len(digestBytes)))
	}
	return IntervalDigest{
		min:    digestBytes[:nIDLen],
		max:    digestBytes[nIDLen : 2*nIDLen],
		digest: digestBytes[2*nIDLen:],
	}
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
	return append(append(d.min, d.max...), d.digest...)
}

func (d IntervalDigest) String() string {
	return fmt.Sprintf(
		`{
  min: %x
  max: %x
  digest: %x
}`, d.min, d.max, d.digest)
}
