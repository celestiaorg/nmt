package nmt

import (
	"reflect"
	"testing"
)

type pathSpan struct {
	squareSize uint
	startNode  uint
	length     uint
}

type pathResult [][][]int

func TestArgValidation(t *testing.T) {
	type test struct {
		input pathSpan
		want  error
	}

	tests := []test{
		{input: pathSpan{squareSize: 0, startNode: 0, length: 0}, want: errNotPowerOf2},
		{input: pathSpan{squareSize: 1, startNode: 0, length: 1}, want: errNotPowerOf2},
		{input: pathSpan{squareSize: 20, startNode: 0, length: 1}, want: errNotPowerOf2},
		{input: pathSpan{squareSize: 4, startNode: 0, length: 17}, want: errPastSquareSize},
		{input: pathSpan{squareSize: 4, startNode: 0, length: 0}, want: errInvalidShareCount},
		{input: pathSpan{squareSize: 128, startNode: 1, length: 18446744073709551615}, want: errInvalidIdxEnd},
	}

	for _, tc := range tests {
		paths, err := GetSubrootPaths(tc.input.squareSize, tc.input.startNode, tc.input.length)
		if err != tc.want {
			t.Fatalf(`GetSubrootPaths(%v) = %v, %v, want %v`, tc.input, paths, err, tc.want)
		}
	}
}

func TestPathGeneration(t *testing.T) {
	type test struct {
		input pathSpan
		want  pathResult
		desc  string
	}

	tests := []test{
		{
			input: pathSpan{squareSize: 2, startNode: 0, length: 2},
			want:  pathResult{{{}}},
			desc:  "Single row span, should return empty to signify one row root",
		},
		{
			input: pathSpan{squareSize: 2, startNode: 0, length: 1},
			want:  pathResult{{{0}}},
			desc:  "Single left-most node span, should return left-most branch",
		},
		{
			input: pathSpan{squareSize: 2, startNode: 1, length: 1},
			want:  pathResult{{{1}}},
			desc:  "Single right-most node span on first row, should return single-row right-most branch",
		},
		{
			input: pathSpan{squareSize: 4, startNode: 1, length: 2},
			want:  pathResult{{{0, 1}, {1, 0}}},
			desc:  "2-node span on unaligned start, should return two branch paths leading to two nodes in the middle of first row's tree",
		},
		{
			input: pathSpan{squareSize: 8, startNode: 1, length: 6},
			want:  pathResult{{{0, 0, 1}, {1, 1, 0}, {0, 1}, {1, 0}}},
			desc:  "Single row span, taking whole row minus start and end nodes, unaligned start and end. Should return two offset paths, two internal paths, in one row",
		},
		{
			input: pathSpan{squareSize: 32, startNode: 16, length: 16},
			want:  pathResult{{{1}}},
			desc:  "Single row span, taking the right half of the first row, should return right (1) branch of one row",
		},
		{
			input: pathSpan{squareSize: 32, startNode: 0, length: 32},
			want:  pathResult{{{}}},
			desc:  "Whole row span of a larger square, should return empty to signify one row root",
		},
		{
			input: pathSpan{squareSize: 32, startNode: 0, length: 64},
			want:  pathResult{{{}}, {{}}},
			desc:  "Whole row span of 2 rows, should return two empty lists to signify two row roots",
		},
		{
			input: pathSpan{squareSize: 32, startNode: 0, length: 96},
			want:  pathResult{{{}}, {{}}, {{}}},
			desc:  "Whole row span of 3 rows, should return three empty lists to signify three row roots",
		},
		{
			input: pathSpan{squareSize: 32, startNode: 18, length: 11},
			want:  pathResult{{{1, 1, 1, 0, 0}, {1, 0, 0, 1}, {1, 0, 1}, {1, 1, 0}}},
			desc:  "Span starting on right side of first row's tree, on an even-index start but not on a power-of-two alignment, ending on an even-index. Should return 4 paths: branch spanning 18-19, branch spanning 20-23, branch spanning 24-28, and single-node path to 29",
		},
		{
			input: pathSpan{squareSize: 32, startNode: 14, length: 18},
			want:  pathResult{{{0, 1, 1, 1}, {1}}},
			desc:  "Span starting on left side of first row's tree, spanning until end of tree. Should return two paths in one row: right-most branch on left side of tree, and whole right side of tree",
		},
		{
			input: pathSpan{squareSize: 32, startNode: 14, length: 17},
			want:  pathResult{{{1, 1, 1, 1, 0}, {0, 1, 1, 1}, {1, 0}, {1, 1, 0}, {1, 1, 1, 0}}},
			desc:  "Span starting on the last branch of the left side of the first row's tree, starting on an even index, ending at the second-to-last branch of the first row's tree, on an even index. Should return 5 paths: branch spanning 14-15, branch spanning 16-23, branch spanning 24-27, branch spanning 28-29, single-node path to 30",
		},
		{
			input: pathSpan{squareSize: 32, startNode: 48, length: 16},
			want:  pathResult{{{1}}},
			desc:  "Span for right side of second row in square. Should return a single branch in a single list, pointing to the first right path of the row within that starting index",
		},
		{
			input: pathSpan{squareSize: 32, startNode: 0, length: 1024},
			want:  pathResult{{{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}, {{}}},
			desc:  "Span for the entire square. Should return 32 empty lists to signify span covers every row in the square",
		},
		{
			input: pathSpan{squareSize: 32, startNode: 988, length: 32},
			want:  pathResult{{{1, 1, 1}}, {{0}, {1, 0}, {1, 1, 0}}},
			desc:  "Span for last two rows in square, should return last branch of second to last row, left half of last row, and two branches on right half of last row",
		},
		{
			input: pathSpan{squareSize: 32, startNode: 992, length: 32},
			want:  pathResult{{{}}},
			desc:  "Span for last row in the square, should return empty list.",
		},
		{
			input: pathSpan{squareSize: 32, startNode: 1023, length: 1},
			want:  pathResult{{{1, 1, 1, 1, 1}}},
			desc:  "Span for last node in the last row in the square, should return a path of 1s",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			paths, err := GetSubrootPaths(tc.input.squareSize, tc.input.startNode, tc.input.length)
			if !reflect.DeepEqual(pathResult(paths), tc.want) {
				t.Fatalf(`GetSubrootPaths(%v) = %v, %v, want %v - rationale: %v`, tc.input, paths, err, tc.want, tc.desc)
			}
		})
	}
}
