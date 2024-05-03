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
	alicePubKeyId, _, _ := ed25519.GenerateKey(rand.Reader)
	bobPubKeyId, bobPrivKeyId, _ := ed25519.GenerateKey(rand.Reader)
	alicePrivKeyEp, _ := ecdh.X25519().GenerateKey(rand.Reader)

	// Encode and decode the message
	var buffer bytes.Buffer
	//Alice (snd) sends to Bob (rcv)
	n, _ := EncodeWriteInit(bobPubKeyId, alicePubKeyId, alicePrivKeyEp, []byte("hallo"), &buffer)
	//Bob (rcv) received the message from Alice (snd)
	testErrorMac(t, buffer.Bytes(), n, bobPrivKeyId, nil, [32]byte{})
	testErrorContent(t, buffer.Bytes(), n, bobPrivKeyId, nil, [32]byte{})
	testErrorSize(t, buffer.Bytes(), n, bobPrivKeyId, nil, [32]byte{})
	testEmpty(t, buffer.Bytes(), n, bobPrivKeyId, nil, [32]byte{})
	m, _ := Decode(buffer.Bytes(), n, bobPrivKeyId, nil, [32]byte{})
	assert.Equal(t, []byte("hallo"), m.PayloadRaw)
}

func TestDecodeInitReply(t *testing.T) {
	// Create a byte slice with the encoded message
	alicePubKeyId, _, _ := ed25519.GenerateKey(rand.Reader)
	bobPubKeyId, bobPrivKeyId, _ := ed25519.GenerateKey(rand.Reader)

	alicePrivKeyEp, _ := ecdh.X25519().GenerateKey(rand.Reader)
	alicePubKeyEp := alicePrivKeyEp.PublicKey()
	bobPrivKeyEp, _ := ecdh.X25519().GenerateKey(rand.Reader)

	var bufferInit bytes.Buffer
	//Alice (snd) -> Bob (rcv)
	n, _ := EncodeWriteInit(bobPubKeyId, alicePubKeyId, alicePrivKeyEp, []byte("hallo"), &bufferInit)
	m, _ := Decode(bufferInit.Bytes(), n, bobPrivKeyId, nil, [32]byte{})

	var bufferInitReply bytes.Buffer
	// Bob (snd) -> Alice (rcv)
	n, _ = EncodeWriteInitReply(alicePubKeyId, bobPubKeyId, alicePubKeyEp, bobPrivKeyEp, []byte("2hallo"), &bufferInitReply)
	testErrorMac(t, bufferInitReply.Bytes(), n, nil, alicePrivKeyEp, [32]byte{})
	testErrorContent(t, bufferInitReply.Bytes(), n, nil, alicePrivKeyEp, [32]byte{})
	testErrorSize(t, bufferInitReply.Bytes(), n, nil, alicePrivKeyEp, [32]byte{})
	testEmpty(t, bufferInitReply.Bytes(), n, nil, alicePrivKeyEp, [32]byte{})
	m, _ = Decode(bufferInitReply.Bytes(), n, nil, alicePrivKeyEp, [32]byte{})
	assert.Equal(t, []byte("2hallo"), m.PayloadRaw)
}

func TestDecodeMsg(t *testing.T) {
	// Create a byte slice with the encoded message
	alicePubKeyId, _, _ := ed25519.GenerateKey(rand.Reader)
	bobPubKeyId, bobPrivKeyId, _ := ed25519.GenerateKey(rand.Reader)

	alicePrivKeyEp, _ := ecdh.X25519().GenerateKey(rand.Reader)
	alicePubKeyEp := alicePrivKeyEp.PublicKey()
	bobPrivKeyEp, _ := ecdh.X25519().GenerateKey(rand.Reader)

	var bufferInit bytes.Buffer
	// Alice (snd) -> Bob (rcv)
	n, _ := EncodeWriteInit(bobPubKeyId, alicePubKeyId, alicePrivKeyEp, []byte("hallo"), &bufferInit)
	m, _ := Decode(bufferInit.Bytes(), n, bobPrivKeyId, nil, [32]byte{})

	var bufferInitReply bytes.Buffer
	// Bob (snd) -> Alice (rcv)
	n, _ = EncodeWriteInitReply(alicePubKeyId, bobPubKeyId, alicePubKeyEp, bobPrivKeyEp, []byte("2hallo"), &bufferInitReply)
	m, _ = Decode(bufferInitReply.Bytes(), n, nil, alicePrivKeyEp, [32]byte{})
	assert.Equal(t, []byte("2hallo"), m.PayloadRaw)

	sharedSecret := m.SharedSecret
	var bufferMsg1 bytes.Buffer
	// Alice (snd) -> Bob (rcv)
	n, _ = EncodeWriteMsg(bobPubKeyId, alicePubKeyId, sharedSecret, []byte("33hallo"), &bufferMsg1)
	testErrorMac(t, bufferMsg1.Bytes(), n, nil, nil, sharedSecret)
	testErrorContent(t, bufferMsg1.Bytes(), n, nil, nil, sharedSecret)
	testErrorSize(t, bufferMsg1.Bytes(), n, nil, nil, sharedSecret)
	testEmpty(t, bufferMsg1.Bytes(), n, nil, nil, sharedSecret)
	m, _ = Decode(bufferMsg1.Bytes(), n, nil, nil, sharedSecret)
	assert.Equal(t, []byte("33hallo"), m.PayloadRaw)

	var bufferMsg2 bytes.Buffer
	// Bob (snd) -> Alice (rcv)
	n, _ = EncodeWriteMsg(alicePubKeyId, bobPubKeyId, sharedSecret, []byte("33hallo"), &bufferMsg2)
	testErrorMac(t, bufferMsg2.Bytes(), n, nil, nil, sharedSecret)
	testErrorContent(t, bufferMsg2.Bytes(), n, nil, nil, sharedSecret)
	testErrorSize(t, bufferMsg2.Bytes(), n, nil, nil, sharedSecret)
	testEmpty(t, bufferMsg2.Bytes(), n, nil, nil, sharedSecret)
	m, _ = Decode(bufferMsg2.Bytes(), n, nil, nil, sharedSecret)
	assert.Equal(t, []byte("33hallo"), m.PayloadRaw)
}

func testErrorMac(t *testing.T, b []byte, n int, privKeyIdRcv ed25519.PrivateKey, privKeyEpRcv *ecdh.PrivateKey, sharedSecret [32]byte) {
	b2 := make([]byte, len(b))
	copy(b2, b)
	b2[len(b)-1] = b2[len(b)-1] + 1
	_, err := Decode(b2, n, privKeyIdRcv, privKeyEpRcv, sharedSecret)
	assert.NotNil(t, err)
}

func testErrorContent(t *testing.T, b []byte, n int, privKeyIdRcv ed25519.PrivateKey, privKeyEpRcv *ecdh.PrivateKey, sharedSecret [32]byte) {
	b2 := make([]byte, len(b))
	copy(b2, b)
	b2[len(b)-17] = b2[len(b)-17] + 1
	_, err := Decode(b2, n, privKeyIdRcv, privKeyEpRcv, sharedSecret)
	assert.NotNil(t, err)
}

func testErrorSize(t *testing.T, b []byte, n int, privKeyIdRcv ed25519.PrivateKey, privKeyEpRcv *ecdh.PrivateKey, sharedSecret [32]byte) {
	b2 := make([]byte, len(b)-1)
	copy(b2, b)
	_, err := Decode(b2, n, privKeyIdRcv, privKeyEpRcv, sharedSecret)
	assert.NotNil(t, err)
}

func testEmpty(t *testing.T, b []byte, n int, privKeyIdRcv ed25519.PrivateKey, privKeyEpRcv *ecdh.PrivateKey, sharedSecret [32]byte) {
	b2 := make([]byte, 0)
	_, err := Decode(b2, n, privKeyIdRcv, privKeyEpRcv, sharedSecret)
	assert.NotNil(t, err)
}
