package nmt

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"runtime"
	"sync"
)

// BatchProcessor handles parallel hash computation for independent subtrees
type BatchProcessor struct {
	maxWorkers int
	hasherPool sync.Pool
}

// NewBatchProcessor creates a new batch processor for parallel hashing
func NewBatchProcessor() *BatchProcessor {
	return &BatchProcessor{
		maxWorkers: runtime.NumCPU(),
		hasherPool: sync.Pool{
			New: func() interface{} {
				return sha256.New()
			},
		},
	}
}

// HashJob represents a single hash computation job
type HashJob struct {
	Left   []byte
	Right  []byte
	Result []byte
	Error  error
}

// BatchHashNodes processes multiple HashNode operations in parallel
// This allows multiple SIMD lanes to be utilized simultaneously
func (bp *BatchProcessor) BatchHashNodes(hasher Hasher, jobs []*HashJob) error {
	if len(jobs) == 0 {
		return nil
	}

	// For small batches, use serial processing to avoid goroutine overhead
	if len(jobs) <= 2 {
		for _, job := range jobs {
			result, err := hasher.HashNode(job.Left, job.Right)
			job.Result = result
			job.Error = err
		}
		return nil
	}

	// Use worker pool for larger batches
	jobChan := make(chan *HashJob, len(jobs))
	var wg sync.WaitGroup

	// Start workers (limited by CPU count)
	numWorkers := bp.maxWorkers
	if numWorkers > len(jobs) {
		numWorkers = len(jobs)
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Create a local hasher for this worker to avoid contention
			baseHash := bp.hasherPool.Get().(hash.Hash)
			localHasher := NewNmtHasher(baseHash, hasher.NamespaceSize(), hasher.IsMaxNamespaceIDIgnored())
			defer bp.hasherPool.Put(baseHash)

			for job := range jobChan {
				result, err := localHasher.HashNode(job.Left, job.Right)
				job.Result = result
				job.Error = err
			}
		}()
	}

	// Send jobs to workers
	for _, job := range jobs {
		jobChan <- job
	}
	close(jobChan)

	// Wait for completion
	wg.Wait()

	// Check for any errors
	for _, job := range jobs {
		if job.Error != nil {
			return fmt.Errorf("batch hash failed: %w", job.Error)
		}
	}

	return nil
}

// ParallelComputeRoot is an optimized version of computeRoot that processes
// independent subtrees in parallel to utilize multiple SIMD lanes
func (n *NamespacedMerkleTree) ParallelComputeRoot(start, end int) ([]byte, error) {
	if start < 0 || start > end || end > n.Size() {
		return nil, fmt.Errorf("failed to compute root [%d, %d): %w", start, end, ErrInvalidRange)
	}

	switch end - start {
	case 0:
		rootHash := n.treeHasher.EmptyRoot()
		n.visit(rootHash)
		return rootHash, nil
	case 1:
		leafHash := make([]byte, len(n.leafHashes[start]))
		copy(leafHash, n.leafHashes[start])
		n.visit(leafHash, n.leaves[start])
		return leafHash, nil
	case 2:
		// For 2 leaves, directly compute without parallelization overhead
		return n.computeRoot(start, end)
	default:
		// For larger ranges, collect parallel work
		return n.computeRootParallel(start, end, 0)
	}
}

// computeRootParallel recursively computes roots while batching parallel operations
func (n *NamespacedMerkleTree) computeRootParallel(start, end, depth int) ([]byte, error) {
	// Base cases - use original logic for small ranges and deep recursion
	if end-start <= 8 || depth > 2 { // Reduced parallelization to avoid hasher contention
		return n.computeRoot(start, end)
	}

	k := getSplitPoint(end - start)
	
	// Create separate hasher instances for thread safety
	leftHasher := NewNmtHasher(sha256.New(), n.treeHasher.NamespaceSize(), n.treeHasher.IsMaxNamespaceIDIgnored())
	rightHasher := NewNmtHasher(sha256.New(), n.treeHasher.NamespaceSize(), n.treeHasher.IsMaxNamespaceIDIgnored())
	
	// Create separate tree instances for parallel processing
	leftTree := &NamespacedMerkleTree{
		leaves:     n.leaves,
		leafHashes: n.leafHashes,
		treeHasher: leftHasher,
		visit:      n.visit,
	}
	rightTree := &NamespacedMerkleTree{
		leaves:     n.leaves,
		leafHashes: n.leafHashes,
		treeHasher: rightHasher,
		visit:      n.visit,
	}

	// Create parallel jobs for left and right subtrees
	type subtreeJob struct {
		start, end int
		result     []byte
		err        error
	}

	leftJob := &subtreeJob{start: start, end: start + k}
	rightJob := &subtreeJob{start: start + k, end: end}

	var wg sync.WaitGroup
	wg.Add(2)

	// Process left subtree
	go func() {
		defer wg.Done()
		leftJob.result, leftJob.err = leftTree.computeRoot(leftJob.start, leftJob.end)
	}()

	// Process right subtree  
	go func() {
		defer wg.Done()
		rightJob.result, rightJob.err = rightTree.computeRoot(rightJob.start, rightJob.end)
	}()

	wg.Wait()

	// Check for errors
	if leftJob.err != nil {
		return nil, fmt.Errorf("failed to compute left subtree [%d, %d): %w", leftJob.start, leftJob.end, leftJob.err)
	}
	if rightJob.err != nil {
		return nil, fmt.Errorf("failed to compute right subtree [%d, %d): %w", rightJob.start, rightJob.end, rightJob.err)
	}

	// Combine results using original hasher
	hash, err := n.treeHasher.HashNode(leftJob.result, rightJob.result)
	if err != nil {
		return nil, fmt.Errorf("failed to hash subtree nodes: %w", err)
	}

	n.visit(hash, leftJob.result, rightJob.result)
	return hash, nil
}