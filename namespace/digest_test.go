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

func TestIntervalDigest_String(t *testing.T) {
	type fields struct {
		min    ID
		max    ID
		digest []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"empty", fields{[]byte{0}, []byte{1}, []byte{}}, "{\n  min: 00\n  max: 01\n  digest: \n}"},
		{"simple", fields{[]byte{0}, []byte{1}, []byte{1, 0, 0}}, "{\n  min: 00\n  max: 01\n  digest: 010000\n}"},
		{"simple", fields{[]byte{0}, []byte{1}, []byte{1, 0, 0, 0, 0, 1}}, "{\n  min: 00\n  max: 01\n  digest: 010000000001\n}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := IntervalDigest{
				min:    tt.fields.min,
				max:    tt.fields.max,
				digest: tt.fields.digest,
			}
			if got := d.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}
