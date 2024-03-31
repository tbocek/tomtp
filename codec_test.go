package tomtp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDecodeInit(t *testing.T) {
	// Create a byte slice with the encoded message
	pubId, privId, _ := ed25519.GenerateKey(rand.Reader)
	var buffer bytes.Buffer
	epPrivKeyCurve, _ := ecdh.X25519().GenerateKey(rand.Reader)

	// EncodeWrite the message
	n, _ := EncodeWriteInit(pubId, pubId, []byte("hallo"), epPrivKeyCurve, &buffer)

	m, _ := Decode(buffer.Bytes(), n, privId, [32]byte{})
	assert.Equal(t, []byte("hallo"), m.Payload.EncryptedData)
}

/*func TestDecodeNotEnoughData(t *testing.T) {
	// Create a byte slice with the encoded message
	encoded := make([]byte, 32+4+len("Hello, world!"))
	copy(encoded[:32], pubId)
	binary.BigEndian.PutUint32(encoded[32:36], 12345)
	copy(encoded[36:], []byte("Hello, world!"))

	// Test with not enough data
	m, err := tomtp.Decode(encoded[:32], len(encoded[:32]))
	assert.Nil(t, err)
	assert.Nil(t, m)
}

func TestCodec(t *testing.T) {
	// Create a new message with random data
	for i := 0; i < 10000; i++ {
		msg := &tomtp.Message{
			PubId:    pubId,
			StreamID: 12345,
			Payload:  make([]byte, 10),
		}
		rand.Read(msg.PubId[:])
		rand.Read(msg.Payload)

		// EncodeWrite the message
		buf := &bytes.Buffer{}
		_, err := tomtp.EncodeWrite(msg, buf)
		assert.NoError(t, err)

		// Decode the message
		decodedMsg, err := tomtp.Decode(buf.Bytes(), buf.Len())
		assert.NoError(t, err)

		// Check if the decoded message matches the original message
		assert.Equal(t, msg, decodedMsg)
	}
}*/
