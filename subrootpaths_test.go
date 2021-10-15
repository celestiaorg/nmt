package nmt

import (
	"reflect"
	"testing"
)

func TestArgValidation(t *testing.T) {

	type test struct {
		input [3]uint
		want  error
	}

	tests := []test{
		{input: [3]uint{0, 0, 0}, want: SRPNotPowerOf2},
		{input: [3]uint{1, 0, 1}, want: SRPNotPowerOf2},
		{input: [3]uint{20, 0, 1}, want: SRPNotPowerOf2},
		{input: [3]uint{4, 0, 17}, want: SRPPastSquareSize},
		{input: [3]uint{4, 0, 0}, want: SRPInvalidShareSize},
	}

	for _, tc := range tests {
		paths, err := GetSubrootPaths(tc.input[0], tc.input[1], tc.input[2])
		if err != tc.want {
			t.Fatalf(`GetSubrootPaths(%v) = %v, %v, want %v`, tc.input, paths, err, tc.want)
		}
	}
}

func TestPathGeneration(t *testing.T) {

	type test struct {
		input [3]uint
		want  [][][]int
	}

	tests := []test{
		{input: [3]uint{2, 0, 2}, want: [][][]int{{{}}}},
		{input: [3]uint{2, 0, 1}, want: [][][]int{{{0}}}},
		{input: [3]uint{2, 1, 1}, want: [][][]int{{{1}}}},
		{input: [3]uint{4, 1, 2}, want: [][][]int{{{0, 1}, {1, 0}}}},
		{input: [3]uint{8, 1, 6}, want: [][][]int{{{0, 0, 1}, {1, 1, 0}, {0, 1}, {1, 0}}}},
		{input: [3]uint{32, 0, 32}, want: [][][]int{{{}}}},
		{input: [3]uint{32, 0, 64}, want: [][][]int{{{}}, {{}}}},
		{input: [3]uint{32, 0, 96}, want: [][][]int{{{}}, {{}}, {{}}}},
		{input: [3]uint{32, 18, 11}, want: [][][]int{{{1, 1, 1, 0, 0}, {1, 0, 0, 1}, {1, 0, 1}, {1, 1, 0}}}},
		{input: [3]uint{32, 14, 18}, want: [][][]int{{{0, 1, 1, 1}, {1}}}},
		{input: [3]uint{32, 48, 16}, want: [][][]int{{{1}}}},
	}

	for _, tc := range tests {
		paths, err := GetSubrootPaths(tc.input[0], tc.input[1], tc.input[2])
		if !reflect.DeepEqual(paths, tc.want) {
			t.Fatalf(`GetSubrootPaths(%v) = %v, %v, want %v`, tc.input, paths, err, tc.want)
		}
	}

}
