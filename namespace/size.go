package namespace

import "math"

// IDSize is the number of bytes a namespace uses.
// Valid values are in [0,255].
type IDSize uint8

// IDMaxSize defines the max. allowed namespace ID size in bytes.
const IDMaxSize = math.MaxUint8
