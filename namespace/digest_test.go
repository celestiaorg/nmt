package namespace

import (
	"testing"
)

func TestIntervalDigestFromBytesPanic(t *testing.T) {
	tests := []struct {
		name        string
		nIDLen      uint8
		digestBytes []byte
	}{
		{"empty digest", 1, []byte(nil)},
		{"too short digest", 1, []byte{1}},
		{"too short digest", 2, []byte{1, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			func() {
				//nolint:errcheck
				defer func() { recover() }()
				IntervalDigestFromBytes(tt.nIDLen, tt.digestBytes)
				t.Errorf("should have panicked")
			}()
		})
	}
}
