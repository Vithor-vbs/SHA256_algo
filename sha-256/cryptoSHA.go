package main

import (
	"fmt"
)

func main() {
	password := "myPassword123"

	// Hash the password using SHA-256
	hash := sha256Hash(password)

	// Convert the hash to a hex string
	hashString := toHexString(hash)

	fmt.Println("Original Password:", password)
	fmt.Println("SHA-256 Hash:", hashString)
}

func sha256Hash(password string) [32]byte {
	data := []byte(password)
	var hash [32]byte // saída com len fixo

	// These values are part of the SHA-256 algorithm specification and are used in the hashing process.
	var h [8]uint32
	h[0] = 0x6a09e667
	h[1] = 0xbb67ae85
	h[2] = 0x3c6ef372
	h[3] = 0xa54ff53a
	h[4] = 0x510e527f
	h[5] = 0x9b05688c
	h[6] = 0x1f83d9ab
	h[7] = 0x5be0cd19

	var k [64]uint32
	k[0] = 0x428a2f98
	k[1] = 0x71374491
	k[2] = 0xb5c0fbcf
	k[3] = 0xe9b5dba5
	k[4] = 0x3956c25b
	k[5] = 0x59f111f1
	k[6] = 0x923f82a4
	k[7] = 0xab1c5ed5
	// k[8] = 0xd807aa98
	// k[9] = 0x12835b01
	// k[10] = 0x243185be
	// k[11] = 0x550c7dc3
	// k[12] = 0x72be5d74
	// k[13] = 0x80deb1fe
	// k[14] = 0x9bdc06a7
	// k[15] = 0xc19bf174
	// k[16] = 0xe49b69c1
	// k[17] = 0xefbe4786
	// k[18] = 0x0fc19dc6
	// k[19] = 0x240ca1cc
	// k[20] = 0x2de92c6f
	// k[21] = 0x4a7484aa
	// k[22] = 0x5cb0a9dc
	// k[23] = 0x76f988da
	// k[24] = 0x983e5152
	// k[25] = 0xa831c66d
	// k[26] = 0xb00327c8
	// k[27] = 0xbf597fc7
	// k[28] = 0xc6e00bf3
	// k[29] = 0xd5a79147
	// k[30] = 0x06ca6351
	// k[31] = 0x14292967
	// k[32] = 0x27b70a85
	// k[33] = 0x2e1b2138
	// k[34] = 0x4d2c6dfc
	// k[35] = 0x53380d13
	// k[36] = 0x650a7354
	// k[37] = 0x766a0abb
	// k[38] = 0x81c2c92e
	// k[39] = 0x92722c85
	// k[40] = 0xa2bfe8a1
	// k[41] = 0xa81a664b
	// k[42] = 0xc24b8b70
	// k[43] = 0xc76c51a3
	// k[44] = 0xd192e819
	// k[45] = 0xd6990624
	// k[46] = 0xf40e3585
	// k[47] = 0x106aa070
	// k[48] = 0x19a4c116
	// k[49] = 0x1e376c08
	// k[50] = 0x2748774c
	// k[51] = 0x34b0bcb5
	// k[52] = 0x391c0cb3
	// k[53] = 0x4ed8aa4a
	// k[54] = 0x5b9cca4f
	// k[55] = 0x682e6ff3
	// k[56] = 0x748f82ee
	// k[57] = 0x78a5636f
	// k[58] = 0x84c87814
	// k[59] = 0x8cc70208
	// k[60] = 0x90befffa
	// k[61] = 0xa4506ceb
	// k[62] = 0xbef9a3f7
	// k[63] = 0xc67178f2

	// Pre-processing: Padding
	data = append(data, 0x80)
	for len(data)%64 != 56 {
		data = append(data, 0x00)
	}
	dataLen := uint64(len(password)) * 8 //length da senha original em bits

	// It appends eight bytes representing the length in big-endian format.
	data = append(data, byte(dataLen>>56), byte(dataLen>>48), byte(dataLen>>40), byte(dataLen>>32), byte(dataLen>>24), byte(dataLen>>16), byte(dataLen>>8), byte(dataLen))

	// Process message in 64-byte blocks
	for i := 0; i < len(data); i += 64 {
		w := make([]uint32, 64) // criação do message schedule

		// Prepare message schedule
		for t := 0; t < 16; t++ { // separa em series de 32 bytes e converte para uint32 e 4 bytes por vez realiza o bitwise e armazena no message schedule
			w[t] = uint32(data[i+t*4])<<24 | uint32(data[i+t*4+1])<<16 | uint32(data[i+t*4+2])<<8 | uint32(data[i+t*4+3])
		}
		for t := 16; t < 64; t++ {
			s0 := rightRotate(w[t-15], 7) ^ rightRotate(w[t-15], 18) ^ (w[t-15] >> 3)
			s1 := rightRotate(w[t-2], 17) ^ rightRotate(w[t-2], 19) ^ (w[t-2] >> 10)
			w[t] = w[t-16] + s0 + w[t-7] + s1
		}

		// Initialize working variables, They hold the current hash values from h[0] to h[7] respectively.
		a := h[0]
		b := h[1]
		c := h[2]
		d := h[3]
		e := h[4]
		f := h[5]
		g := h[6]
		hh := h[7]

		// Compression function: This part executes the main compression function of SHA-256. It iterates 64 times, performing various bitwise operations and calculations to update the working variables and produce the final hash.
		for t := 0; t < 64; t++ {
			s1 := rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)
			ch := (e & f) ^ (^e & g)
			temp1 := hh + s1 + ch + k[t] + w[t]
			s0 := rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)
			maj := (a & b) ^ (a & c) ^ (b & c)
			temp2 := s0 + maj

			hh = g
			g = f
			f = e
			e = d + temp1
			d = c
			c = b
			b = a
			a = temp1 + temp2
		}

		// the working variables are added to the corresponding elements of the h array to update the hash values.
		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
		h[4] += e
		h[5] += f
		h[6] += g
		h[7] += hh
	}

	// Convert the final hash to [32]byte array
	// It extracts individual bytes from each hash value using bitwise right-shift operations and assigns them to the hash array.
	for i := 0; i < 8; i++ {
		hash[i*4] = byte(h[i] >> 24)
		hash[i*4+1] = byte(h[i] >> 16)
		hash[i*4+2] = byte(h[i] >> 8)
		hash[i*4+3] = byte(h[i])
	}

	return hash
}

// his function performs a right rotation on a 32-bit unsigned integer (value). It takes two parameters: value, the value to be rotated, and bits, the number of bits to rotate by. The function performs a right shift by bits positions and combines it with a left shift by 32 - bits positions using bitwise OR operations to achieve the rotation effect. The rotated value is then returned.
func rightRotate(value uint32, bits uint32) uint32 {
	return (value >> bits) | (value << (32 - bits))
}

func toHexString(data [32]byte) string {
	hexChars := "0123456789abcdef"
	hexString := ""
	for _, b := range data {
		hexString += string(hexChars[b>>4])
		hexString += string(hexChars[b&0x0f])
	}
	return hexString
}
