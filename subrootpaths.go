package nmt

import (
	"errors"
	"math"
)

var (
	srpNotPowerOf2      = errors.New("GetSubrootPaths: Supplied square size is not a power of 2")
	srpInvalidShareSize = errors.New("GetSubrootPaths: Can't compute path for 0 length share slice")
	srpPastSquareSize   = errors.New("GetSubrootPaths: Share slice can't be past the square size")
)

func subdivide(idxStart uint, width uint) []int {
	var path []int
	pathlen := int(math.Log2(float64(width)))
	for i := pathlen - 1; i >= 0; i-- {
		if (idxStart & (1 << i)) == 0 {
			path = append(path, 0)
		} else {
			path = append(path, 1)
		}
	}
	return path
}

func extractBranch(path []int, index int, offset int, branch int) []int {
	rightCapture := make([]int, len(path))
	copy(rightCapture, path)
	rightCapture[index] = branch
	return rightCapture[:index+offset]
}

func prune(idxStart uint, idxEnd uint, maxWidth uint) [][]int {

	var prunedPaths [][]int
	var preprocessedPaths [][]int

	pathStart := subdivide(idxStart, maxWidth)
	pathEnd := subdivide(idxEnd, maxWidth)

	// special case of two-share length, just return one or two paths
	if idxStart+1 >= idxEnd {
		if idxStart%2 == 1 {
			return append(prunedPaths, pathStart, pathEnd)
		} else {
			return append(prunedPaths, pathStart[:len(pathStart)-1])
		}
	}

	// if starting share is on an odd index, add that single path and shift it right 1
	if idxStart%2 == 1 {
		idxStart++
		preprocessedPaths = append(preprocessedPaths, pathStart)
		pathStart = subdivide(idxStart, maxWidth)
	}

	// if ending share is on an even index, add that single index and shift it left 1
	if idxEnd%2 == 0 {
		idxEnd--
		preprocessedPaths = append(preprocessedPaths, pathEnd)
	}

	treeDepth := len(pathStart)
	capturedSpan := uint(0)
	rightTraversed := false

	for i := treeDepth - 1; i >= 0 && capturedSpan < idxEnd; i-- {
		nodeSpan := uint(math.Pow(float64(2), float64(treeDepth-i)))
		if pathStart[i] == 0 {
			// if nodespan is less than end index, continue traversing upwards
			lastNode := nodeSpan + idxStart - 1
			if lastNode <= idxEnd {
				capturedSpan = lastNode
				// if a right path has been encountered, we want to return the right
				// branch one level down
				if rightTraversed {
					prunedPaths = append(prunedPaths, extractBranch(pathStart, i, 1, 1))
				} else {
					// else add *just* the current root node
					prunedPaths = [][]int{pathStart[:i]}
				}
			} else {
				// else if it's greater than the end index, break out of the left-capture loop
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

	// if the process captured the span to the end, return the results
	if capturedSpan == idxEnd {
		return append(preprocessedPaths, prunedPaths...)
	}

	// else recurse into the leftover span
	combined := append(preprocessedPaths, prunedPaths...)
	newStart := capturedSpan + 1
	return append(combined, prune(newStart, idxEnd, maxWidth)...)
}

// GetSubrootPaths is a pure function that takes arguments: square size, share index start,
// and share length, and returns a minimal set of paths to the subtree roots that
// encompasses that entire range of shares, with each top level entry in the list
// starting from the nearest row root.
//
// An empty entry in the top level list means the shares span that entire row and so
// the root for that segment of shares is equivalent to the row root.
func GetSubrootPaths(squareSize uint, idxStart uint, shareLen uint) ([][][]int, error) {

	var paths [][]int
	var top [][][]int

	shares := squareSize * squareSize

	// check if squareSize is a power of 2 by checking that only 1 bit is on
	if squareSize < 2 || !((squareSize & (squareSize - 1)) == 0) {
		return nil, srpNotPowerOf2
	}

	// no path exists for 0 length slice
	if shareLen == 0 {
		return nil, srpInvalidShareSize
	}

	// adjust for 0 index
	shareLen = shareLen - 1

	// sanity checking
	if idxStart >= shares || idxStart+shareLen >= shares {
		return nil, srpPastSquareSize
	}

	startRow := int(math.Floor(float64(idxStart) / float64(squareSize)))
	endRow := int(math.Ceil(float64(idxStart+shareLen) / float64(squareSize)))

	shareStart := idxStart % squareSize
	shareEnd := (idxStart + shareLen) % squareSize

	// if the length is one, just return the subdivided start path
	if shareLen == 0 {
		return append(top, append(paths, subdivide(shareStart, squareSize))), nil
	}

	// if the shares are all in one row, do the normal case
	if startRow == endRow-1 {
		top = append(top, prune(shareStart, shareEnd, squareSize))
	} else {
		// if the shares span multiple rows, treat it as 2 different path generations,
		// one from left-most root to end of a row, and one from start of a row to right-most root,
		// and returning nil lists for the fully covered rows in between=
		left, _ := GetSubrootPaths(squareSize, shareStart, squareSize-shareStart)
		right, _ := GetSubrootPaths(squareSize, 0, shareEnd+1)
		top = append(top, left[0])
		for i := 1; i < (endRow-startRow)-1; i++ {
			top = append(top, [][]int{{}})
		}
		top = append(top, right[0])
	}

	return top, nil
}
