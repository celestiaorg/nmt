package nmt

import (
	"crypto/sha256"
	
	"github.com/celestiaorg/nmt/namespace"
)

// DirectSIMDTreeBuilder builds trees with minimal allocations and optimized data flow
type DirectSIMDTreeBuilder struct {
	hasher    *NmtHasher
	nsLen     int
	nodeCache [][]byte // Reusable node storage
}

// NewDirectSIMDTreeBuilder creates an allocation-optimized tree builder  
func NewDirectSIMDTreeBuilder(nsLen int) *DirectSIMDTreeBuilder {
	return &DirectSIMDTreeBuilder{
		hasher:    NewNmtHasher(sha256.New(), namespace.IDSize(nsLen), true),
		nsLen:     nsLen,
		nodeCache: make([][]byte, 0, 1024), // Pre-allocate large cache
	}
}

// ComputeRootDirect uses optimized single-pass tree building
// Key optimization: reuse allocations and optimize memory access patterns
func (d *DirectSIMDTreeBuilder) ComputeRootDirect(leafHashes [][]byte) ([]byte, error) {
	if len(leafHashes) == 0 {
		return d.hasher.EmptyRoot(), nil
	}
	if len(leafHashes) == 1 {
		return leafHashes[0], nil
	}

	// Reset cache for reuse
	d.nodeCache = d.nodeCache[:0]
	
	// Copy initial level
	currentLevel := make([][]byte, len(leafHashes))
	copy(currentLevel, leafHashes)

	// Build tree level by level with optimized allocations
	for len(currentLevel) > 1 {
		nextLevelSize := (len(currentLevel) + 1) / 2
		
		// Reuse cache if possible, otherwise extend
		if cap(d.nodeCache) < nextLevelSize {
			d.nodeCache = make([][]byte, nextLevelSize)
		} else {
			d.nodeCache = d.nodeCache[:nextLevelSize]
		}
		
		nextLevel := d.nodeCache
		nextIdx := 0
		
		// Process pairs with minimal allocations
		for i := 0; i < len(currentLevel); i += 2 {
			if i+1 < len(currentLevel) {
				// Hash pair with pre-allocated hasher
				left := currentLevel[i]
				right := currentLevel[i+1]
				
				// Direct namespace extraction (avoid allocations)
				leftMinNs := left[:d.nsLen]
				leftMaxNs := left[d.nsLen:2*d.nsLen]
				rightMinNs := right[:d.nsLen]
				rightMaxNs := right[d.nsLen:2*d.nsLen]
				
				// Validate ordering with vectorized comparison
				if VectorizedNamespaceCompare(rightMinNs, leftMaxNs) < 0 {
					return nil, ErrUnorderedSiblings
				}
				
				// Compute namespace range
				minNs := leftMinNs
				maxNs := rightMaxNs
				
				// Direct hash computation
				d.hasher.Reset()
				d.hasher.baseHasher.Write([]byte{NodePrefix})
				d.hasher.baseHasher.Write(left)
				d.hasher.baseHasher.Write(right)
				hashResult := d.hasher.baseHasher.Sum(nil)
				
				// Build result with minimal copying
				resultLen := len(minNs) + len(maxNs) + len(hashResult)
				result := make([]byte, resultLen)
				copy(result[:len(minNs)], minNs)
				copy(result[len(minNs):len(minNs)+len(maxNs)], maxNs)
				copy(result[len(minNs)+len(maxNs):], hashResult)
				
				nextLevel[nextIdx] = result
				nextIdx++
			} else {
				// Odd node - promote to next level
				nextLevel[nextIdx] = currentLevel[i]
				nextIdx++
			}
		}
		
		// Update for next iteration
		currentLevel = nextLevel[:nextIdx]
	}

	return currentLevel[0], nil
}