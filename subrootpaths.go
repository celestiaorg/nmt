package main

import (
	"errors"
	"fmt"
	"math"
)

func subdivide(idxStart uint, width uint) []int {
	var path []int
	if width == 1 {
		return path
	}
	center := width / 2
	if idxStart < center {
		path = append(path, 0)
	} else {
		idxStart -= center
		path = append(path, 1)
	}
	return append(path, subdivide(idxStart, center)...)
}

func prune(idxStart uint, pathStart []int, idxEnd uint, pathEnd []int, maxWidth uint) [][]int {

	var prunedPaths [][]int

	// special case of two-share length
	if idxStart+1 >= idxEnd {
		if idxStart%2 == 1 {
			return append(prunedPaths, pathStart, pathEnd)
		} else {
			return append(prunedPaths, pathStart[:len(pathStart)-1])
		}
	}

	// if starting share is on an odd index
	if idxStart%2 == 1 {
		idxStart += 1
		prunedPaths = append(prunedPaths, pathStart)
		pathStart = subdivide(idxStart, maxWidth)
	}

	// if ending share is on an even index
	if idxEnd%2 == 0 {
		idxEnd -= 1
		prunedPaths = append(prunedPaths, pathEnd)
		pathEnd = subdivide(idxEnd, maxWidth)
	}

	treeDepth := len(pathStart)
	capturedSpan := uint(0)
	rightTraversed := false

	for i := 1; i < treeDepth; i++ {
		nodeSpan := uint(math.Pow(float64(2), float64(i)))
		if pathStart[len(pathStart)-i] == 0 {
			if (nodeSpan+idxStart)-1 < idxEnd {
				// if nodespan is less than end index, continue traversing upwards
				capturedSpan = nodeSpan
				if rightTraversed {
					rightCapture := make([]int, len(pathStart))
					copy(rightCapture, pathStart)
					rightCapture[len(pathStart)-i] = 1
					rightCapture = rightCapture[:treeDepth-(i-1)]
					prunedPaths = append(prunedPaths, rightCapture)
				} else {
					rightCapture := make([]int, len(pathStart)-i)
					copy(rightCapture, pathStart[:len(pathStart)-i])
					rightCapture[len(pathStart)-i-1] = 1
					prunedPaths = append(prunedPaths, rightCapture)
				}
			} else if (nodeSpan+idxStart)-1 == idxEnd {
				if rightTraversed {
					rightCapture := make([]int, len(pathStart))
					copy(rightCapture, pathStart)
					rightCapture[len(pathStart)-i] = 1
					rightCapture = rightCapture[:treeDepth-(i-1)]
					prunedPaths = append(prunedPaths, rightCapture)
					return prunedPaths
				} else {
					rightCapture := make([]int, len(pathStart))
					copy(rightCapture, pathStart)
					//rightCapture[len(pathStart)-i] = 1
					rightCapture = rightCapture[:treeDepth-i]
					prunedPaths = append(prunedPaths, rightCapture)
					return prunedPaths
				}
			} else {
				// else if it's greater than the end index, break out of the left-capture loop
				capturedSpan = nodeSpan/2 - 1
				break
			}
		} else {
			// on a right upwards traverse, we skip processing
			// besides adjusting the idxStart for span calculation
			// and modifying the previous path calculations to not include
			// containing roots as they would span beyond the start index
			idxStart = idxStart - nodeSpan/2
			rightTraversed = true
		}
	}

	var outPath []int

	for i := 1; i < treeDepth; i++ {
		// if we ever reach a left branch connection on this loop we've found the final slice
		if pathEnd[len(pathEnd)-i] == 0 {
			if outPath == nil {
				outPath = pathEnd[:len(pathEnd)-(i-1)]
			}
			break
		} else {
			nodeSpan := uint(math.Pow(float64(2), float64(i)))
			if int(idxEnd)-int(nodeSpan) <= int(capturedSpan) {
				rightCapture := make([]int, len(pathEnd))
				copy(rightCapture, pathEnd)
				rightCapture[len(pathEnd)-i] = 1
				rightCapture = rightCapture[:treeDepth-(i)]
				outPath = rightCapture
			} else {
				continue
			}
		}
	}

	prunedPaths = append(prunedPaths, outPath)

	return prunedPaths
}

// Pure function that takes arguments: square size, share index start,
// and share length, and returns a minimal path to the subtree root that
// encompasses that entire range, with the path starting from the
// nearest row root.
func GetSubrootPaths(squareSize uint, idxStart uint, shareLen uint) ([][]int, error) {

	var paths [][]int
	shares := squareSize * squareSize

	if shareLen == 0 {
		return nil, errors.New("GetSubrootPaths: Can't compute path for 0 length share slice")
	}

	// adjust for 0 index
	shareLen = shareLen - 1

	// sanity checking
	if idxStart >= shares || idxStart+shareLen >= shares {
		return nil, errors.New("GetSubrootPaths: Share slice can't be past the square size")
	}

	startRow := int(math.Floor(float64(idxStart) / float64(squareSize)))
	endRow := int(math.Ceil(float64(idxStart+shareLen) / float64(squareSize)))

	shareStart := idxStart % squareSize
	shareEnd := (idxStart + shareLen) % squareSize

	pathStart := subdivide(shareStart, squareSize)
	pathEnd := subdivide(shareEnd, squareSize)

	subtreeLvls := int(math.Log2(float64(squareSize))) - 1

	if shareLen == 0 {
		paths = append(paths, pathStart)
		return paths, nil
	}

	if startRow == endRow-1 {
		paths = append(paths, prune(shareStart, pathStart, shareEnd, pathEnd, squareSize)...)
	} else {
		prune(shareStart, pathStart, squareSize-1, make([]int, subtreeLvls, subtreeLvls), squareSize)
		prune(0, make([]int, subtreeLvls, subtreeLvls), shareEnd, pathEnd, squareSize)
	}

	return paths, nil
}

func main() {
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
	//	fmt.Println(getSubrootPaths(32, 1, 16))
	//	fmt.Println(getSubrootPaths(32, 0, 16))
}
