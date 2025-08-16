package nmt

import (
	"crypto/sha256"
	"testing"

	"github.com/celestiaorg/nmt/namespace"
)

// BenchmarkSIMDOptimizations tests the performance impact of SIMD optimizations
func BenchmarkSIMDOptimizations(b *testing.B) {
	namespaceIDSize := namespace.IDSize(8)
	
	// Create test tree with multiple leaves
	tree := New(sha256.New(), NamespaceIDSize(int(namespaceIDSize)), IgnoreMaxNamespace(true))
	
	// Add test data
	for i := 0; i < 64; i++ {
		data := make([]byte, int(namespaceIDSize)+100)
		// Create namespace
		for j := 0; j < int(namespaceIDSize); j++ {
			data[j] = byte(i)
		}
		// Add some payload data
		for j := int(namespaceIDSize); j < len(data); j++ {
			data[j] = byte((i + j) % 256)
		}
		err := tree.Push(data)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.Run("OriginalComputeRoot", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := tree.computeRoot(0, tree.Size())
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ParallelComputeRoot", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := tree.ParallelComputeRoot(0, tree.Size())
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkNamespaceComparison tests vectorized namespace operations
func BenchmarkNamespaceComparison(b *testing.B) {
	// Create test namespace IDs
	nsA := make([]byte, 29) // Celestia namespace size
	nsB := make([]byte, 29)
	
	for i := range nsA {
		nsA[i] = byte(i)
		nsB[i] = byte(i + 1)
	}

	idA := namespace.ID(nsA)
	idB := namespace.ID(nsB)

	b.Run("OriginalComparison", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = idA.Less(idB)
		}
	})

	b.Run("VectorizedComparison", func(b *testing.B) {
		ops := &VectorizedNamespaceOps{}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = ops.FastCompare(idA, idB) < 0
		}
	})

	// Test batch operations
	pairs := make([]NamespacePair, 1000)
	for i := range pairs {
		pairs[i] = NamespacePair{A: idA, B: idB}
	}

	b.Run("BatchComparison", func(b *testing.B) {
		ops := &VectorizedNamespaceOps{}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = ops.BatchCompareNamespaces(pairs)
		}
	})
}