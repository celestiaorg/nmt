package nmt

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"unsafe"

	"github.com/celestiaorg/nmt/namespace"
)

// BenchmarkTrueSIMD tests actual SIMD lane utilization vs threading
func BenchmarkTrueSIMD(b *testing.B) {
	namespaceSize := 29 // Celestia namespace size
	testData := make([][]byte, 8)
	
	// Create test namespace data
	for i := range testData {
		data := make([]byte, namespaceSize)
		for j := 0; j < namespaceSize-4; j++ {
			data[j] = 0
		}
		// Properly ordered namespace
		data[namespaceSize-4] = byte(i >> 24)
		data[namespaceSize-3] = byte(i >> 16) 
		data[namespaceSize-2] = byte(i >> 8)
		data[namespaceSize-1] = byte(i)
		testData[i] = data
	}

	b.Run("OriginalNamespaceCompare", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for j := 1; j < len(testData); j++ {
				idA := namespace.ID(testData[j-1])
				idB := namespace.ID(testData[j])
				_ = idA.Less(idB)
			}
		}
	})

	b.Run("VectorizedNamespaceCompare", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for j := 1; j < len(testData); j++ {
				_ = VectorizedNamespaceCompare(testData[j-1], testData[j])
			}
		}
	})

	b.Run("AssemblyNamespaceCompare", func(b *testing.B) {
		// Pad to 32 bytes for AVX2 processing
		paddedData := make([][]byte, len(testData))
		for i, data := range testData {
			padded := make([]byte, 32)
			copy(padded, data)
			paddedData[i] = padded
		}
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for j := 1; j < len(paddedData); j++ {
				aPtr := (*byte)(unsafe.Pointer(&paddedData[j-1][0]))
				bPtr := (*byte)(unsafe.Pointer(&paddedData[j][0]))
				_ = vectorizedNamespaceCompare(aPtr, bPtr)
			}
		}
	})
}

// BenchmarkSIMDHashBatching tests true SIMD hash processing
func BenchmarkSIMDHashBatching(b *testing.B) {
	namespaceIDSize := namespace.IDSize(8)
	
	// Create batch of leaf data for SIMD processing
	batchSizes := []int{4, 8, 16}
	
	for _, batchSize := range batchSizes {
		b.Run(fmt.Sprintf("Sequential-%d-hashes", batchSize), func(b *testing.B) {
			hasher := NewNmtHasher(sha256.New(), namespaceIDSize, true)
			
			// Create test batch
			batch := make([][]byte, batchSize)
			for i := range batch {
				data := make([]byte, int(namespaceIDSize)+100)
				for j := 0; j < int(namespaceIDSize); j++ {
					data[j] = byte(i)
				}
				for j := int(namespaceIDSize); j < len(data); j++ {
					data[j] = byte((i + j) % 256)
				}
				batch[i] = data
			}
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, data := range batch {
					_, err := hasher.HashLeaf(data)
					if err != nil {
						b.Fatal(err)
					}
					hasher.Reset()
				}
			}
		})
		
		b.Run(fmt.Sprintf("SIMD-Batched-%d-hashes", batchSize), func(b *testing.B) {
			simdHasher := NewSIMDHasher(sha256.New(), namespaceIDSize, true)
			
			// Create same test batch
			batch := make([][]byte, batchSize)
			for i := range batch {
				data := make([]byte, int(namespaceIDSize)+100)
				for j := 0; j < int(namespaceIDSize); j++ {
					data[j] = byte(i)
				}
				for j := int(namespaceIDSize); j < len(data); j++ {
					data[j] = byte((i + j) % 256)
				}
				batch[i] = data
			}
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := simdHasher.BatchHashLeaves(batch)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkMemoryLayoutSIMD tests SIMD-optimized memory operations
func BenchmarkMemoryLayoutSIMD(b *testing.B) {
	namespaceLen := 29
	ns1 := make([]byte, namespaceLen)
	ns2 := make([]byte, namespaceLen)
	
	// Fill with test data
	for i := range ns1 {
		ns1[i] = byte(i)
		ns2[i] = byte(i + 1)
	}

	b.Run("StandardMemoryCopy", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			result := make([]byte, namespaceLen*2)
			copy(result[:namespaceLen], ns1)
			copy(result[namespaceLen:], ns2)
			_ = result
		}
	})

	b.Run("SIMDMemoryCopy", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			result := make([]byte, namespaceLen*2)
			// Use vectorized memory copy (when available)
			if namespaceLen <= 32 {
				batchMemoryCopy(
					unsafe.Pointer(&result[0]),
					unsafe.Pointer(&ns1[0]), 
					unsafe.Pointer(&ns2[0]),
					namespaceLen,
				)
			} else {
				// Fallback to standard copy for large namespaces
				copy(result[:namespaceLen], ns1)
				copy(result[namespaceLen:], ns2)
			}
			_ = result
		}
	})
}