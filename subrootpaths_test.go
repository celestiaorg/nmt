package nmt

import (
	"fmt"
	"testing"
)

func TestPathGeneration(t *testing.T) {
	//	fmt.Println(getSubrootPaths(8, 0, 7))
	//	fmt.Println(getSubrootPaths(8, 3, 1))
	//	fmt.Println(getSubrootPaths(8, 2, 3))
	//	fmt.Println(getSubrootPaths(8, 2, 4))
	//	fmt.Println(getSubrootPaths(8, 0, 2))
	fmt.Println("32, 0, 4")
	fmt.Println(GetSubrootPaths(32, 0, 4))
	fmt.Println("32, 1, 8")
	fmt.Println(GetSubrootPaths(32, 1, 8))
	fmt.Println("32, 1, 11")
	fmt.Println(GetSubrootPaths(32, 1, 11))
	fmt.Println("32, 18, 11")
	fmt.Println(GetSubrootPaths(32, 18, 11))
	fmt.Println("4, 0, 1")
	fmt.Println(GetSubrootPaths(4, 0, 1))
	fmt.Println("16, 0, 8")
	fmt.Println(GetSubrootPaths(16, 0, 8))
	//	fmt.Println(getSubrootPaths(32, 1, 16))
	//	fmt.Println(getSubrootPaths(32, 0, 16))
}
