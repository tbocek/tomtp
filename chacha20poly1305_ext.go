package tomtp

import (
	"encoding/binary"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/poly1305"
)

// inspired by: https://github.com/golang/crypto/blob/master/chacha20poly1305/chacha20poly1305_generic.go
func openNoVerify(sharedSecret []byte, nonce []byte, encoded []byte) (mac []byte, snSer []byte) {
	// Generate the Poly1305 key using ChaCha20
	var polyKey [32]byte
	s, _ := chacha20.NewUnauthenticatedCipher(sharedSecret, nonce)
	s.XORKeyStream(polyKey[:], polyKey[:])
	s.SetCounter(1) // Set the counter to 1, skipping 32 bytes

	// Initialize Poly1305 with the derived key
	p := poly1305.New(&polyKey)
	writeWithPadding(p, encoded)
	writeUint64(p, 0) //no additional data
	writeUint64(p, len(encoded))

	// Decrypt the ciphertext
	snSer = make([]byte, 8)
	s.XORKeyStream(snSer, encoded)

	// Calculate the MAC (Poly1305 tag)
	mac = p.Sum(nil)

	return mac, snSer
}

func writeWithPadding(p *poly1305.MAC, b []byte) {
	p.Write(b)
	if rem := len(b) % 16; rem != 0 {
		var buf [16]byte
		padLen := 16 - rem
		p.Write(buf[:padLen])
	}
}

func writeUint64(p *poly1305.MAC, n int) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(n))
	p.Write(buf[:])
}
