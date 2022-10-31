package nmt

import (
	"strconv"
	"strings"
	"testing"
)

func TestPrune(t *testing.T) {
	_ = prune(1, 3, 0)
	_ = subdivide(0, 0)
}

func FuzzPrune(f *testing.F) {
	if testing.Short() {
		f.Skip("skipping")
	}

	// Add the fuzzer seeds.
	f.Add("0*0*0")
	f.Add("0*0*1")
	f.Add("0*1*1")
	f.Add("1*0*0")
	f.Add("1*1*0")
	f.Add("1*3*0")
	f.Add("127*18*40")
	f.Add("64*0*4")
	f.Add("2*0*0")
	f.Add("128*9*20")
	f.Add("8*9*20")
	f.Add("3*9*20")

	f.Fuzz(func(t *testing.T, in string) {
		sp := strings.Split(in, "*")
		if len(sp) != 3 {
			return
		}
		prune(mustUint(t, sp[0]), mustUint(t, sp[1]), mustUint(t, sp[2]))
	})

}

func mustUint(t *testing.T, s string) uint {
	u, _ := strconv.ParseUint(s, 10, 0)
	return uint(u)
}

func FuzzGetSubrootPaths(f *testing.F) {
	if testing.Short() {
		f.Skip("skipping")
	}
	f.Add("64*0*4")
	f.Add("2*0*0")
	f.Add("128*9*20")
	f.Add("8*9*20")
	f.Add("3*9*20")

	f.Fuzz(func(t *testing.T, in string) {
		sp := strings.Split(in, "*")
		if len(sp) != 3 {
			return
		}
		GetSubrootPaths(mustUint(t, sp[0]), mustUint(t, sp[1]), mustUint(t, sp[2]))
	})
}
