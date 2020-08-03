package nmt_test

import (
	"crypto"
	"testing"

	"github.com/lazyledger/nmt"
	"github.com/lazyledger/nmt/defaulthasher"
	"github.com/lazyledger/nmt/namespace"
)

func TestProof_VerifyNamespace_ExpectedErrors(t *testing.T) {
	const testNidLen = 3
	nmthash := defaulthasher.New(testNidLen, crypto.SHA256)

	n := nmt.New(nmthash)
	data := append([]namespace.PrefixedData{
		namespace.NewPrefixedData(3, []byte{0, 0, 0, 3, 4, 5})},
		generateLeafData(testNidLen, 0, 9, []byte("data"))...,
	)
	for _, d := range data {
		err := n.Push(d)
		if err != nil {
			t.Fatalf("invalid test setup: error on Push(): %v", err)
		}
	}

	validProof, err := n.ProveNamespace([]byte{0, 0, 0})
	if err != nil {
		t.Fatalf("invalid test setup: error on ProveNamespace(): %v", err)
	}
	type args struct {
		nID  namespace.ID
		data []namespace.PrefixedData
		root namespace.IntervalDigest
	}
	pushedZeroNs := n.Get([]byte{0, 0, 0})
	tests := []struct {
		name      string
		proof     nmt.Proof
		args      args
		want      bool
		wantErr   bool
		wantPanic bool
	}{
		{"invalid nid (too long)", validProof,
			args{[]byte{0, 0, 0, 0}, pushedZeroNs, n.Root()},
			false, true, false},
		{"mismatching IDs in data", validProof,
			args{[]byte{0, 0, 0}, append(append([]namespace.PrefixedData(nil), pushedZeroNs...), namespace.NewPrefixedData(testNidLen, []byte{1, 1, 1})), n.Root()},
			false, true, false},
		{"added another leaf", validProof,
			args{[]byte{0, 0, 0}, append(append([]namespace.PrefixedData(nil), pushedZeroNs...), namespace.NewPrefixedData(testNidLen, []byte{0, 0, 0})), n.Root()},
			false, true, false},
		{"remove one leaf, errors", validProof,
			args{[]byte{0, 0, 0}, pushedZeroNs[:len(pushedZeroNs)-1], n.Root()},
			false, true, false},
		{"remove all leaves, errors", validProof,
			args{[]byte{0, 0, 0}, pushedZeroNs[:len(pushedZeroNs)-2], n.Root()},
			false, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				func() {
					//nolint:errcheck
					defer func() { recover() }()
					//nolint:errcheck
					tt.proof.VerifyNamespace(nmthash, tt.args.nID, tt.args.data, tt.args.root)
					t.Errorf("should have panicked")
				}()
			} else {
				got, err := tt.proof.VerifyNamespace(nmthash, tt.args.nID, tt.args.data, tt.args.root)
				if (err != nil) != tt.wantErr {
					t.Errorf("VerifyNamespace() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if got != tt.want {
					t.Errorf("VerifyNamespace() got = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
