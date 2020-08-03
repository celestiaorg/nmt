package namespace

import "fmt"

type IntervalDigest struct {
	min    ID
	max    ID
	digest []byte
}

func NewIntervalDigest(min, max ID, digest []byte) IntervalDigest {
	return IntervalDigest{
		min:    min,
		max:    max,
		digest: digest,
	}
}

func IntervalDigestFromBytes(nIDLen uint8, digestBytes []byte) IntervalDigest {
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
	return fmt.Sprintf("{min:%x, max:%x, digest:%x}", d.min, d.max, d.digest)
}
