package nmt

import (
	"sync"
)

// SIMDTreeComputer implements level-by-level SIMD tree computation
type SIMDTreeComputer struct {
	shaNIHasher *SHANIBatchHasher
	leafData    [][]byte
	pools       sync.Pool
}

// NewSIMDTreeComputer creates a SIMD-optimized tree computer
func NewSIMDTreeComputer() *SIMDTreeComputer {
	return &SIMDTreeComputer{
		shaNIHasher: NewSHANIBatchHasher(8, true),
		pools: sync.Pool{
			New: func() interface{} {
				return make([][]byte, 0, 64)
			},
		},
	}
}

// ComputeRootSIMD processes tree construction using level-by-level SIMD batching
// This is the key optimization: instead of recursive HashNode calls,
// we batch all HashNode operations at each tree level for SIMD processing
func (s *SIMDTreeComputer) ComputeRootSIMD(leafHashes [][]byte) ([]byte, error) {
	if len(leafHashes) == 0 {
		// Return empty root - would need to implement for SHANIBatchHasher
		return nil, nil
	}
	if len(leafHashes) == 1 {
		return leafHashes[0], nil
	}

	// Start with leaf level
	currentLevel := make([][]byte, len(leafHashes))
	copy(currentLevel, leafHashes)

	// Process each tree level with SIMD batching
	for len(currentLevel) > 1 {
		nextLevel, err := s.processSIMDLevel(currentLevel)
		if err != nil {
			return nil, err
		}
		currentLevel = nextLevel
	}

	return currentLevel[0], nil
}

// processSIMDLevel processes an entire tree level using SIMD batch operations
// This is where the real SIMD optimization happens - instead of individual
// HashNode calls, we batch them for vectorized processing
func (s *SIMDTreeComputer) processSIMDLevel(level [][]byte) ([][]byte, error) {
	if len(level) <= 1 {
		return level, nil
	}

	// Calculate next level size
	nextLevelSize := (len(level) + 1) / 2
	nextLevel := make([][]byte, 0, nextLevelSize)

	// Process pairs in batches for SIMD optimization
	const simdBatchSize = 8 // Process 8 HashNode operations simultaneously

	for i := 0; i < len(level); i += simdBatchSize * 2 {
		batchEnd := i + simdBatchSize*2
		if batchEnd > len(level) {
			batchEnd = len(level)
		}

		// Extract pairs for this SIMD batch
		var leftNodes, rightNodes [][]byte
		for j := i; j < batchEnd; j += 2 {
			if j+1 < len(level) {
				// Normal pair
				leftNodes = append(leftNodes, level[j])
				rightNodes = append(rightNodes, level[j+1])
			} else {
				// Odd number - promote single node
				nextLevel = append(nextLevel, level[j])
			}
		}

		// Process all pairs in this batch using SHA-NI optimization
		if len(leftNodes) > 0 {
			batchResults, err := s.shaNIHasher.BatchHashNodes(leftNodes, rightNodes)
			if err != nil {
				return nil, err
			}
			nextLevel = append(nextLevel, batchResults...)
		}
	}

	return nextLevel, nil
}


// ComputeRoot method for NamespacedMerkleTree using SIMD optimization  
func (n *NamespacedMerkleTree) ComputeRootSIMD() ([]byte, error) {
	if n.rawRoot != nil {
		return n.rawRoot, nil
	}

	simdComputer := NewSIMDTreeComputer()
	root, err := simdComputer.ComputeRootSIMD(n.leafHashes)
	if err != nil {
		return nil, err
	}

	n.rawRoot = root
	return root, nil
}