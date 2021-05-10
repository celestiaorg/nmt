package namespace

import (
	"testing"
)

func TestIntervalDigestFromBytesPanic(t *testing.T) {
	tests := []struct {
		name        string
		nIDLen      IDSize
		digestBytes []byte
	}{
		{"empty digest", 1, []byte(nil)},
		{"too short digest", 1, []byte{1}},
		{"too short digest", 2, []byte{1, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			func() {
				_, err := IntervalDigestFromBytes(tt.nIDLen, tt.digestBytes)
				if err == nil {
					t.Errorf("should have errored")
				}
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
				Min:    tt.fields.min,
				Max:    tt.fields.max,
				Digest: tt.fields.digest,
			}
			if got := d.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIntervalDigest_Equal(t *testing.T) {
	tests := []struct {
		name     string
		one, two *IntervalDigest
		want     bool
	}{
		{
			"equal",
			&IntervalDigest{[]byte{0}, []byte{1}, []byte{}},
			&IntervalDigest{[]byte{0}, []byte{1}, []byte{}},
			true,
		},
		{
			"unequal",
			&IntervalDigest{[]byte{0}, []byte{1}, []byte{1, 0, 0}},
			&IntervalDigest{[]byte{0}, []byte{1}, []byte{1, 1, 1}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.one.Equal(tt.two); got != tt.want {
				t.Errorf("Equal() = %v, want %v", got, tt.want)
			}
		})
	}
}
