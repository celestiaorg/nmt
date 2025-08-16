package nmt

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/celestiaorg/nmt/namespace"
)

// BenchmarkLargeTreeSIMD tests SIMD benefits on large trees where parallelization matters
func BenchmarkLargeTreeSIMD(b *testing.B) {
	sizes := []int{256, 1024, 4096}
	namespaceIDSize := namespace.IDSize(8)

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Original-%d-leaves", size), func(b *testing.B) {
			tree := New(sha256.New(), NamespaceIDSize(int(namespaceIDSize)), IgnoreMaxNamespace(true))
			
			// Add test data with properly ordered namespaces
			for i := 0; i < size; i++ {
				data := make([]byte, int(namespaceIDSize)+100)
				// Create properly ordered namespace: pad with zeros and put index at end
				for j := 0; j < int(namespaceIDSize)-4; j++ {
					data[j] = 0
				}
				// Put i in the last 4 bytes in big-endian format for proper ordering
				data[int(namespaceIDSize)-4] = byte(i >> 24)
				data[int(namespaceIDSize)-3] = byte(i >> 16)
				data[int(namespaceIDSize)-2] = byte(i >> 8)
				data[int(namespaceIDSize)-1] = byte(i)
				
				for j := int(namespaceIDSize); j < len(data); j++ {
					data[j] = byte((i + j) % 256)
				}
				err := tree.Push(data)
				if err != nil {
					b.Fatal(err)
				}
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := tree.computeRoot(0, tree.Size())
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("Parallel-%d-leaves", size), func(b *testing.B) {
			tree := New(sha256.New(), NamespaceIDSize(int(namespaceIDSize)), IgnoreMaxNamespace(true))
			
			// Add same test data with properly ordered namespaces
			for i := 0; i < size; i++ {
				data := make([]byte, int(namespaceIDSize)+100)
				// Create properly ordered namespace: pad with zeros and put index at end
				for j := 0; j < int(namespaceIDSize)-4; j++ {
					data[j] = 0
				}
				// Put i in the last 4 bytes in big-endian format for proper ordering
				data[int(namespaceIDSize)-4] = byte(i >> 24)
				data[int(namespaceIDSize)-3] = byte(i >> 16)
				data[int(namespaceIDSize)-2] = byte(i >> 8)
				data[int(namespaceIDSize)-1] = byte(i)
				
				for j := int(namespaceIDSize); j < len(data); j++ {
					data[j] = byte((i + j) % 256)
				}
				err := tree.Push(data)
				if err != nil {
					b.Fatal(err)
				}
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := tree.ParallelComputeRoot(0, tree.Size())
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}