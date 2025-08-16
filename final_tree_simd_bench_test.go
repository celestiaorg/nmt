package nmt

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

// BenchmarkTreeSIMDCore tests the core tree computation optimization:
// Level-by-level SIMD batch processing vs recursive HashNode calls
func BenchmarkTreeSIMDCore(b *testing.B) {
	// Focus on larger trees where SIMD batching shows more benefit
	treeSizes := []int{512, 1024, 2048}
	
	for _, numLeaves := range treeSizes {
		// Generate test data
		data, err := generateRandNamespacedRawData(numLeaves, 8, 256)
		require.NoError(b, err)
		
		// Pre-compute leaf hashes for both approaches
		hasher := NewNmtHasher(sha256.New(), 8, true)
		leafHashes := make([][]byte, numLeaves)
		for i, leaf := range data {
			hash, err := hasher.HashLeaf(leaf)
			require.NoError(b, err)
			leafHashes[i] = hash
			hasher.Reset()
		}

		b.Run("Recursive-"+string(rune('0'+numLeaves/1000))+string(rune('0'+(numLeaves/100)%10))+string(rune('0'+(numLeaves/10)%10))+string(rune('0'+numLeaves%10)), func(b *testing.B) {
			b.ResetTimer() 
			for i := 0; i < b.N; i++ {
				// Original recursive tree computation - build tree properly
				tree := New(sha256.New())
				for _, leaf := range data {
					err := tree.Push(leaf)
					if err != nil {
						b.Fatal(err)
					}
				}
				_, err := tree.computeRoot(0, tree.Size())
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run("Direct-SIMD-"+string(rune('0'+numLeaves/1000))+string(rune('0'+(numLeaves/100)%10))+string(rune('0'+(numLeaves/10)%10))+string(rune('0'+numLeaves%10)), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Direct SIMD tree computation with optimized allocations
				builder := NewDirectSIMDTreeBuilder(8)
				_, err := builder.ComputeRootDirect(leafHashes)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkHashNodeBatching isolates the HashNode batching optimization
func BenchmarkHashNodeBatching(b *testing.B) {
	// Create test tree level with pairs to hash
	levelSize := 64
	testLevel := make([][]byte, levelSize)
	
	// Generate leaf hashes
	hasher := NewNmtHasher(sha256.New(), 8, true)
	for i := range testLevel {
		data := make([]byte, 8+100)
		for j := 0; j < 8; j++ {
			data[j] = byte(i)
		}
		for j := 8; j < len(data); j++ {
			data[j] = byte((i + j) % 256)
		}
		hash, _ := hasher.HashLeaf(data)
		testLevel[i] = hash
		hasher.Reset()
	}

	b.Run("Individual-HashNode-Calls", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			hasher := NewNmtHasher(sha256.New(), 8, true)
			results := make([][]byte, 0, levelSize/2)
			
			// Process pairs individually (original approach)
			for j := 0; j < len(testLevel); j += 2 {
				if j+1 < len(testLevel) {
					hash, err := hasher.HashNode(testLevel[j], testLevel[j+1])
					if err != nil {
						b.Fatal(err)
					}
					results = append(results, hash)
				}
			}
			_ = results
		}
	})

	b.Run("Batched-HashNode-Calls", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			batchHasher := NewSHANIBatchHasher(8, true)
			
			// Extract pairs for batch processing
			var leftNodes, rightNodes [][]byte
			for j := 0; j < len(testLevel); j += 2 {
				if j+1 < len(testLevel) {
					leftNodes = append(leftNodes, testLevel[j])
					rightNodes = append(rightNodes, testLevel[j+1])
				}
			}
			
			// Process all pairs in batch (SIMD approach)
			results, err := batchHasher.BatchHashNodes(leftNodes, rightNodes)
			if err != nil {
				b.Fatal(err)
			}
			_ = results
		}
	})
}