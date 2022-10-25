package nmt

import (
	"errors"
	"math"
	"math/bits"
)

var (
	srpNotPowerOf2       = errors.New("GetSubrootPaths: Supplied square size is not a power of 2")
	srpInvalidShareCount = errors.New("GetSubrootPaths: Can't compute path for 0 share count slice")
	srpPastSquareSize    = errors.New("GetSubrootPaths: Share slice can't be past the square size")
)

// merkle path to a node is equivalent to the index's binary representation
// this is just a quick function to return that representation as a list of ints
func subdivide(idxStart uint, width uint) []int {
	var path []int
	pathlen := int(bits.Len(width) - 1)
	for i := pathlen - 1; i >= 0; i-- {
		if (idxStart & (1 << i)) == 0 {
			path = append(path, 0)
		} else {
			path = append(path, 1)
		}
	}
	return path
}

// this function takes a path, and returns a copy of that path with path[index] set to branch,
// and cuts off the list at path[:index+offset] - used to create inclusion branches during traversal
func extractBranch(path []int, index int, offset int, branch int) []int {
	rightCapture := make([]int, len(path))
	copy(rightCapture, path)
	rightCapture[index] = branch
	return rightCapture[:index+offset]
}

func prune(idxStart uint, idxEnd uint, maxWidth uint) [][]int {
	if idxEnd == 0 || maxWidth == 0 {
		return nil
	}
	if idxStart > idxEnd || idxEnd >= maxWidth {
		return nil
	}

	pathStart := subdivide(idxStart, maxWidth)
	pathEnd := subdivide(idxEnd, maxWidth)

	// special case of two-share path, just return one or two paths
	if idxStart+1 >= idxEnd {
		if idxStart%2 == 1 {
			return [][]int{pathStart, pathEnd}
		} else {
			return [][]int{pathStart[:len(pathStart)-1]}
		}
	}

	var prunedPaths [][]int
	var preprocessedPaths [][]int

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
		// nodeSpan is 2**(treeDepth-i) == 1<<(treeDepth-i)
		// Please see: https://github.com/celestiaorg/nmt/issues/72
		nodeSpan := uint(1 << (treeDepth - i))
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

	combined := append(preprocessedPaths, prunedPaths...)
	// if the process captured the span to the end, return the results
	if capturedSpan == idxEnd {
		return combined
	}
	// else recurse into the leftover span
	return append(combined, prune(capturedSpan+1, idxEnd, maxWidth)...)
}

// GetSubrootPaths is a pure function that takes arguments: square size, share index start,
// and share Count, and returns a minimal set of paths to the subtree roots that
// encompasses that entire range of shares, with each top level entry in the list
// starting from the nearest row root.
//
// An empty entry in the top level list means the shares span that entire row and so
// the root for that segment of shares is equivalent to the row root.
func GetSubrootPaths(squareSize uint, idxStart uint, shareCount uint) ([][][]int, error) {

	var paths [][]int
	var top [][][]int

	shares := squareSize * squareSize

	// check squareSize is at least 2 and that it's
	// a power of 2 by checking that only 1 bit is on
	if squareSize < 2 || bits.OnesCount(squareSize) != 1 {
		return nil, srpNotPowerOf2
	}

	// no path exists for 0 count slice
	if shareCount == 0 {
		return nil, srpInvalidShareCount
	}

	// sanity checking
	if idxStart >= shares || idxStart+shareCount > shares {
		return nil, srpPastSquareSize
	}

	// adjust for 0 index
	shareCount = shareCount - 1

	startRow := int(math.Floor(float64(idxStart) / float64(squareSize)))
	closingRow := int(math.Ceil(float64(idxStart+shareCount) / float64(squareSize)))

	shareStart := idxStart % squareSize
	shareEnd := (idxStart + shareCount) % squareSize

	// if the count is one, just return the subdivided start path
	if shareCount == 0 {
		return append(top, append(paths, subdivide(shareStart, squareSize))), nil
	}

	// if the shares are all in one row, do the normal case
	if startRow == closingRow-1 {
		top = append(top, prune(shareStart, shareEnd, squareSize))
	} else {
		// if the shares span multiple rows, treat it as 2 different path generations,
		// one from left-most root to end of a row, and one from start of a row to right-most root,
		// and returning nil lists for the fully covered rows in between
		left, _ := GetSubrootPaths(squareSize, shareStart, squareSize-shareStart)
		right, _ := GetSubrootPaths(squareSize, 0, shareEnd+1)
		top = append(top, left[0])
		for i := 1; i < (closingRow-startRow)-1; i++ {
			top = append(top, [][]int{{}})
		}
		top = append(top, right[0])
	}

	return top, nil
}
