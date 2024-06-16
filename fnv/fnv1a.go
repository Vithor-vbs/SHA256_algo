package main

import (
	"fmt"
)

func main() {
	password := "myPassword123"

	// Hash usando FNV-1a
	hash := fnv1aHash(password)

	fmt.Println("Original Password:", password)
	fmt.Println("Hash:", hash)
}

func fnv1aHash(data string) uint32 {
	// FNV-1a constants
	const (
		offsetBasis = 2166136261
		prime       = 16777619
	)

	var hash uint32 = offsetBasis
	for _, b := range []byte(data) {
		hash ^= uint32(b)
		hash *= prime
	}

	return hash
}
