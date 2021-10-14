package nmt

import (
	"errors"
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

func extractBranch(path []int, depth int, index int, offset int) []int {
	rightCapture := make([]int, len(path))
	copy(rightCapture, path)
	rightCapture[len(path)-index] = 1
	rightCapture = rightCapture[:depth-(index-offset)]
	return rightCapture
}

func prune(idxStart uint, pathStart []int, idxEnd uint, pathEnd []int, maxWidth uint) [][]int {

	var prunedPaths [][]int
	var preprocessedPaths [][]int

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
		idxStart += 1
		preprocessedPaths = append(preprocessedPaths, pathStart)
		pathStart = subdivide(idxStart, maxWidth)
	}

	// if ending share is on an even index, add that single index and shift it left 1
	if idxEnd%2 == 0 {
		idxEnd -= 1
		preprocessedPaths = append(preprocessedPaths, pathEnd)
		pathEnd = subdivide(idxEnd, maxWidth)
	}

	treeDepth := len(pathStart)
	capturedSpan := uint(0)
	rightTraversed := false

	for i := 1; i < treeDepth; i++ {
		nodeSpan := uint(math.Pow(float64(2), float64(i)))
		if pathStart[len(pathStart)-i] == 0 {
			// if nodespan is less than end index, continue traversing upwards
			if (nodeSpan+idxStart)-1 < idxEnd {
				capturedSpan = nodeSpan
				// if a right path has been encountered, we want to return the right
				// branch one level down
				if rightTraversed {
					prunedPaths = append(prunedPaths, extractBranch(pathStart, treeDepth, i, 1))
				} else {
					// else add the current root node
					prunedPaths = append(prunedPaths, extractBranch(pathStart, treeDepth, i, 0))
				}
			} else if (nodeSpan+idxStart)-1 == idxEnd {
				// if it's equal to the end index, this is the final root to return
				if rightTraversed {
					prunedPaths = append(prunedPaths, extractBranch(pathStart, treeDepth, i, 1))
					return append(preprocessedPaths, prunedPaths...)
				} else {
					// if we've never traversed right then this is a special case
					// where the last root found here encompasses the whole lower tree
					return append(preprocessedPaths, pathStart[:treeDepth-i])
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
				// traverse upwards while updating the latest path found
				outPath = extractBranch(pathEnd, treeDepth, i, 0)
			}
		}
	}

	prunedPaths = append(prunedPaths, outPath)

	return append(preprocessedPaths, prunedPaths...)
}

// Pure function that takes arguments: square size, share index start,
// and share length, and returns a minimal path to the subtree root that
// encompasses that entire range, with the path starting from the
// nearest row root.
func GetSubrootPaths(squareSize uint, idxStart uint, shareLen uint) ([][]int, error) {

	var paths [][]int
	shares := squareSize * squareSize

	// no path exists for 0 length slice
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

	// if the length is one, just return the subdivided start path
	if shareLen == 0 {
		paths = append(paths, pathStart)
		return paths, nil
	}

	// if the shares are all in one row, do the normal case
	if startRow == endRow-1 {
		paths = append(paths, prune(shareStart, pathStart, shareEnd, pathEnd, squareSize)...)
	} else {
		// if the shares span multiple rows, treat it as 2 different path generations,
		// one from left-most root to end of a row, and one from start of a row to right-most root,
		// and returning nil lists for the fully covered rows in between
		rightEndPath := subdivide(squareSize-1, squareSize)
		leftEndPath := subdivide(0, squareSize)
		paths = append(paths, prune(shareStart, pathStart, squareSize-1, rightEndPath, squareSize)...)
		for i := 0; i < (endRow-startRow)-1; i++ {
			var p []int
			paths = append(paths, p)
		}
		paths = append(paths, prune(0, leftEndPath, shareEnd, pathEnd, squareSize)...)
	}

	return paths, nil
}
