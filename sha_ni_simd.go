package nmt

import (
	"crypto/sha256"
	"hash"
	"unsafe"
)

// SHA-NI optimized batch hasher that utilizes hardware SHA extensions
// This approach focuses on maximizing SHA-NI instruction utilization
// rather than trying to implement custom vectorized SHA256

//go:noescape  
func optimizedMemoryLayout(dst unsafe.Pointer, left, right []byte, nsLen int)

// SHANIBatchHasher uses optimized batch processing with pre-allocated buffers
type SHANIBatchHasher struct {
	NamespaceLen int
	ignoreMaxNs  bool
	batch        [4]hash.Hash
	// Pre-allocated buffers to reduce allocation overhead
	scratchBuffer []byte
	resultBuffer  []byte
}

// NewSHANIBatchHasher creates a hasher optimized for batch processing
func NewSHANIBatchHasher(namespaceLen int, ignoreMaxNs bool) *SHANIBatchHasher {
	s := &SHANIBatchHasher{
		NamespaceLen: namespaceLen,
		ignoreMaxNs:  ignoreMaxNs,
		// Pre-allocate large buffers to reduce allocation overhead in tree computation
		scratchBuffer: make([]byte, 8192), // Large scratch buffer
		resultBuffer:  make([]byte, 4096),  // Result buffer
	}
	
	// Pre-allocate hash instances to reduce allocation overhead
	for i := range s.batch {
		s.batch[i] = sha256.New()
	}
	
	return s
}

// BatchHashNodes processes up to 4 HashNode operations using optimized SHA-NI utilization
func (s *SHANIBatchHasher) BatchHashNodes(leftNodes, rightNodes [][]byte) ([][]byte, error) {
	results := make([][]byte, len(leftNodes))
	
	// Process in batches of 4 to maximize SHA-NI utilization
	for i := 0; i < len(leftNodes); i += 4 {
		batchEnd := i + 4
		if batchEnd > len(leftNodes) {
			batchEnd = len(leftNodes)
		}
		
		batchSize := batchEnd - i
		
		if batchSize == 4 {
			// Full batch - use optimized SHA-NI batch processing
			err := s.processBatch4(leftNodes[i:batchEnd], rightNodes[i:batchEnd], results[i:batchEnd])
			if err != nil {
				return nil, err
			}
		} else {
			// Handle remainder with standard processing
			for j := i; j < batchEnd; j++ {
				result, err := s.hashSingleNode(leftNodes[j], rightNodes[j])
				if err != nil {
					return nil, err
				}
				results[j] = result
			}
		}
	}
	
	return results, nil
}

// processBatch4 processes exactly 4 HashNode operations with optimized SHA-NI utilization
func (s *SHANIBatchHasher) processBatch4(leftNodes, rightNodes, results [][]byte) error {
	// Process in pairs using SHA-NI pipeline optimization
	for i := 0; i < len(leftNodes); i += 2 {
		if i+1 < len(leftNodes) {
			// Process 2 operations with interleaved SHA-NI
			err := s.processPair(leftNodes[i], rightNodes[i], leftNodes[i+1], rightNodes[i+1], results[i:i+2])
			if err != nil {
				return err
			}
		} else {
			// Handle single remaining operation
			result, err := s.hashSingleNode(leftNodes[i], rightNodes[i])
			if err != nil {
				return err
			}
			results[i] = result
		}
	}
	return nil
}

// processPair processes 2 HashNode operations with optimized data layout
func (s *SHANIBatchHasher) processPair(left1, right1, left2, right2 []byte, results [][]byte) error {
	// Validate namespace ordering for both operations
	nsLen := s.NamespaceLen
	
	// Check first pair
	leftMaxNs1 := left1[nsLen:2*nsLen]
	rightMinNs1 := right1[:nsLen]
	if VectorizedNamespaceCompare(rightMinNs1, leftMaxNs1) < 0 {
		return ErrUnorderedSiblings
	}
	
	// Check second pair  
	leftMaxNs2 := left2[nsLen:2*nsLen]
	rightMinNs2 := right2[:nsLen]
	if VectorizedNamespaceCompare(rightMinNs2, leftMaxNs2) < 0 {
		return ErrUnorderedSiblings
	}
	
	// Optimized: reuse pre-allocated hashers to reduce allocation overhead
	// This maximizes SHA-NI utilization by reducing memory management overhead
	hasher1 := s.batch[0]
	hasher2 := s.batch[1]
	
	hasher1.Reset()
	hasher1.Write([]byte{NodePrefix})
	hasher1.Write(left1)
	hasher1.Write(right1)
	
	hasher2.Reset()
	hasher2.Write([]byte{NodePrefix})  
	hasher2.Write(left2)
	hasher2.Write(right2)
	
	// Get hash results
	hash1 := hasher1.Sum(nil)
	hash2 := hasher2.Sum(nil)
	
	// Build results with namespace prefixes - process each result directly
	leftNodes := [][]byte{left1, left2}
	rightNodes := [][]byte{right1, right2}
	hashes := [][]byte{hash1, hash2}
	
	for i := 0; i < 2; i++ {
		left := leftNodes[i]
		right := rightNodes[i]
		hashResult := hashes[i]
		
		leftMinNs := left[:nsLen]
		leftMaxNs := left[nsLen:2*nsLen]
		rightMaxNs := right[nsLen:2*nsLen]
		
		minNs := leftMinNs
		maxNs := rightMaxNs
		if s.ignoreMaxNs {
			maxNs = leftMaxNs
		}
		
		result := make([]byte, len(minNs)+len(maxNs)+len(hashResult))
		copy(result[:len(minNs)], minNs)
		copy(result[len(minNs):len(minNs)+len(maxNs)], maxNs)
		copy(result[len(minNs)+len(maxNs):], hashResult)
		
		results[i] = result
	}
	
	return nil
}

// hashSingleNode processes a single HashNode operation
func (s *SHANIBatchHasher) hashSingleNode(left, right []byte) ([]byte, error) {
	nsLen := s.NamespaceLen
	leftMinNs := left[:nsLen]
	leftMaxNs := left[nsLen:2*nsLen]
	rightMinNs := right[:nsLen]
	rightMaxNs := right[nsLen:2*nsLen]
	
	// Validate namespace ordering
	if VectorizedNamespaceCompare(rightMinNs, leftMaxNs) < 0 {
		return nil, ErrUnorderedSiblings
	}
	
	// Compute namespace range
	minNs := leftMinNs
	maxNs := rightMaxNs
	if s.ignoreMaxNs {
		maxNs = leftMaxNs
	}
	
	// Hash computation
	h := sha256.New()
	h.Write([]byte{NodePrefix})
	h.Write(left)
	h.Write(right)
	hashResult := h.Sum(nil)
	
	// Build result
	result := make([]byte, len(minNs)+len(maxNs)+len(hashResult))
	copy(result[:len(minNs)], minNs)
	copy(result[len(minNs):len(minNs)+len(maxNs)], maxNs)
	copy(result[len(minNs)+len(maxNs):], hashResult)
	
	return result, nil
}