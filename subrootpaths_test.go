package nmt

import (
	"reflect"
	"testing"
)

func TestArgValidation(t *testing.T) {
	var err error
	var paths [][][]int

	paths, err = GetSubrootPaths(0, 0, 0)
	if err == nil {
		t.Fatalf(`GetSubrootPaths(0, 0, 0) = %v, %v, want square size error`, paths, err)
	}

	paths, err = GetSubrootPaths(1, 0, 1)
	if err == nil {
		t.Fatalf(`GetSubrootPaths(1, 0, 1) = %v, %v, want square size error`, paths, err)
	}

	paths, err = GetSubrootPaths(20, 0, 1)
	if err == nil {
		t.Fatalf(`GetSubrootPaths(20, 0, 1) = %v, %v, want square size error`, paths, err)
	}

	paths, err = GetSubrootPaths(4, 0, 17)
	if err == nil {
		t.Fatalf(`GetSubrootPaths(4, 0, 17) = %v, %v, want length past square size error`, paths, err)
	}

	paths, err = GetSubrootPaths(4, 0, 0)
	if err == nil {
		t.Fatalf(`GetSubrootPaths(4, 0, 0) = %v, %v, want invalid share size error`, paths, err)
	}
}

func TestPathGeneration(t *testing.T) {

	var err error
	var paths [][][]int

	paths, err = GetSubrootPaths(2, 0, 2)
	{
		check := [][][]int{{{}}}
		if !reflect.DeepEqual(paths, check) {
			t.Fatalf(`GetSubrootPaths(2, 0, 2) = %v, %v, want %v`, paths, err, check)
		}
	}

	paths, err = GetSubrootPaths(2, 0, 1)
	{
		check := [][][]int{{{0}}}
		if !reflect.DeepEqual(paths, check) {
			t.Fatalf(`GetSubrootPaths(2, 0, 1) = %v, %v, want %v`, paths, err, check)
		}
	}

	paths, err = GetSubrootPaths(2, 1, 1)
	{
		check := [][][]int{{{1}}}
		if !reflect.DeepEqual(paths, check) {
			t.Fatalf(`GetSubrootPaths(2, 1, 1) = %v, %v, want %v`, paths, err, check)
		}
	}

	paths, err = GetSubrootPaths(8, 1, 6)
	{
		check := [][][]int{{{0, 0, 1}, {1, 1, 0}, {0, 1}, {1, 0}}}
		if !reflect.DeepEqual(paths, check) {
			t.Fatalf(`GetSubrootPaths(8, 1, 6) = %v, %v, want %v`, paths, err, check)
		}
	}

	paths, err = GetSubrootPaths(32, 0, 32)
	{
		check := [][][]int{{{}}}
		if !reflect.DeepEqual(paths, check) {
			t.Fatalf(`GetSubrootPaths(32, 0, 32) = %v, %v, want %v`, paths, err, check)
		}
	}

	paths, err = GetSubrootPaths(32, 0, 64)
	{
		check := [][][]int{{{}}, {{}}}
		if !reflect.DeepEqual(paths, check) {
			t.Fatalf(`GetSubrootPaths(32, 0, 64) = %v, %v, want %v`, paths, err, check)
		}
	}

	paths, err = GetSubrootPaths(32, 0, 96)
	{
		check := [][][]int{{{}}, {{}}, {{}}}
		if !reflect.DeepEqual(paths, check) {
			t.Fatalf(`GetSubrootPaths(32, 0, 96) = %v, %v, want %v`, paths, err, check)
		}
	}

	paths, err = GetSubrootPaths(32, 18, 11)
	{
		check := [][][]int{{{1, 1, 1, 0, 0}, {1, 0, 0, 1}, {1, 0, 1}, {1, 1, 0}}}
		if !reflect.DeepEqual(paths, check) {
			t.Fatalf(`GetSubrootPaths(32, 18, 11) = %v, %v, want %v`, paths, err, check)
		}
	}

	paths, err = GetSubrootPaths(32, 48, 16)
	{
		check := [][][]int{{{1}}}
		if !reflect.DeepEqual(paths, check) {
			t.Fatalf(`GetSubrootPaths(32, 18, 11) = %v, %v, want %v`, paths, err, check)
		}
	}
}
