package nmt

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

// BenchmarkTreeComputationSIMD compares recursive vs SIMD level-by-level tree building
func BenchmarkTreeComputationSIMD(b *testing.B) {
	b.ReportAllocs()
	tests := []struct {
		name      string
		numLeaves int
		nidSize   int
		dataSize  int
	}{
		{"64-leaves", 64, 8, 256},
		{"128-leaves", 128, 8, 256},
		{"256-leaves", 256, 8, 256},
		{"1024-leaves", 1024, 8, 256},
		{"4096-leaves", 4096, 8, 256},
	}

	for _, tt := range tests {
		// Generate test data once
		data, err := generateRandNamespacedRawData(tt.numLeaves, tt.nidSize, tt.dataSize)
		require.NoError(b, err)

		b.Run(tt.name+"-Original", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Original recursive tree computation
				n := New(sha256.New())
				for j := 0; j < tt.numLeaves; j++ {
					if err := n.Push(data[j]); err != nil {
						b.Errorf("err: %v", err)
					}
				}
				_, err := n.Root()
				if err != nil {
					b.Errorf("root err: %v", err)
				}
			}
		})

		b.Run(tt.name+"-SIMD", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// SIMD level-by-level tree computation
				n := New(sha256.New())
				for j := 0; j < tt.numLeaves; j++ {
					if err := n.Push(data[j]); err != nil {
						b.Errorf("err: %v", err)
					}
				}
				_, err := n.ComputeRootSIMD()
				if err != nil {
					b.Errorf("SIMD root err: %v", err)
				}
			}
		})
	}
}

// BenchmarkSIMDLevelProcessing tests the core SIMD level processing
func BenchmarkSIMDLevelProcessing(b *testing.B) {
	computer := NewSIMDTreeComputer()
	
	// Create test levels of different sizes
	levelSizes := []int{8, 16, 32, 64, 128}
	
	for _, size := range levelSizes {
		// Generate leaf hashes for this level
		testLevel := make([][]byte, size)
		for i := range testLevel {
			hasher := NewNmtHasher(sha256.New(), 8, true)
			data := make([]byte, 8+100) // namespace + data
			for j := 0; j < 8; j++ {
				data[j] = byte(i) // namespace
			}
			for j := 8; j < len(data); j++ {
				data[j] = byte((i + j) % 256) // data
			}
			hash, _ := hasher.HashLeaf(data)
			testLevel[i] = hash
		}

		b.Run("Original-Level-"+string(rune('0'+size/10))+string(rune('0'+size%10)), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Process level using original recursive method
				hasher := NewNmtHasher(sha256.New(), 8, true)
				results := make([][]byte, 0, len(testLevel)/2)
				for j := 0; j < len(testLevel); j += 2 {
					if j+1 < len(testLevel) {
						hash, err := hasher.HashNode(testLevel[j], testLevel[j+1])
						if err != nil {
							b.Fatal(err)
						}
						results = append(results, hash)
					} else {
						results = append(results, testLevel[j])
					}
				}
				_ = results
			}
		})

		b.Run("SIMD-Level-"+string(rune('0'+size/10))+string(rune('0'+size%10)), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Process level using SIMD batching
				nextLevel, err := computer.processSIMDLevel(testLevel)
				if err != nil {
					b.Fatal(err)
				}
				_ = nextLevel
			}
		})
	}
}