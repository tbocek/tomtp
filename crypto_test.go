package tomtp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"log/slog"
	"testing"
)

func TestDoubleEncryptDecrypt(t *testing.T) {
	// Test parameters
	sn := uint64(1234567890)
	sharedSecret := make([]byte, 32) //randomBytes(32) // 32 bytes
	data := []byte("This is the secret data to encrypt")
	//data := []byte("This")
	additionalData := []byte("Additional authenticated data")

	// Buffer to write the encrypted data
	var buf bytes.Buffer

	// Call doubleEncrypt
	n, err := chainedEncrypt(sn, sharedSecret, additionalData, data, &buf)
	if err != nil {
		t.Fatalf("doubleEncrypt failed: %v", err)
	}
	t.Logf("Encrypted bytes written: %d", n)

	// Read the encrypted data from the buffer
	packet := buf.Bytes()

	// Verify the encryption was successful
	if len(packet) == 0 {
		t.Fatalf("No encrypted data written")
	}
	t.Logf("Encrypted data: %s", hex.EncodeToString(packet))

	// Call doubleDecrypt
	decryptedSn, decryptedData, err := chainedDecrypt(sharedSecret, packet[0:len(additionalData)], packet[len(additionalData):])
	if err != nil {
		t.Fatalf("doubleDecrypt failed: %v", err)
	}

	// Verify that the decrypted data matches the original data
	if sn != decryptedSn {
		t.Errorf("Decrypted SN does not match original SN. Got %d, expected %d", decryptedSn, sn)
	}
	if !bytes.Equal(data, decryptedData) {
		t.Errorf("Decrypted data does not match original data. Got %s, expected %s", decryptedData, data)
	} else {
		t.Logf("Decrypted data matches original data.")
	}
}

func TestSecretKey(t *testing.T) {
	bobPrivKeyId, _ := ecdh.X25519().GenerateKey(rand.Reader)
	bobPubKeyId := bobPrivKeyId.PublicKey()
	alicePrivKeyEp, _ := ecdh.X25519().GenerateKey(rand.Reader)
	alicePubKeyEp := alicePrivKeyEp.PublicKey()

	secret1, _ := bobPrivKeyId.ECDH(alicePubKeyEp)
	secret2, _ := alicePrivKeyEp.ECDH(bobPubKeyId)

	assert.Equal(t, secret1, secret2)
}

func TestDecodeInit(t *testing.T) {
	// Create a byte slice with the encoded message
	alicePrivKeyId, _ := ecdh.X25519().GenerateKey(rand.Reader)
	alicePubKeyId := alicePrivKeyId.PublicKey()

	bobPrivKeyId, _ := ecdh.X25519().GenerateKey(rand.Reader)
	bobPubKeyId := bobPrivKeyId.PublicKey()
	alicePrivKeyEp, _ := ecdh.X25519().GenerateKey(rand.Reader)
	bobPrivKeyEp, _ := ecdh.X25519().GenerateKey(rand.Reader)

	// Encode and decode the message
	var buffer bytes.Buffer
	//Alice (snd) sends to Bob (rcv)
	n, _ := EncodeWriteInit(bobPubKeyId, alicePubKeyId, alicePrivKeyEp, 77, []byte("hallo"), &buffer)
	//Bob (rcv) received the message from Alice (snd)
	testErrorMac(t, buffer.Bytes(), n, bobPrivKeyId, nil, nil, nil)
	testErrorContent(t, buffer.Bytes(), n, bobPrivKeyId, nil, nil, nil)
	testErrorSize(t, buffer.Bytes(), n, bobPrivKeyId, nil, nil, nil)
	testEmpty(t, buffer.Bytes(), n, bobPrivKeyId, nil, nil, nil)
	m, _ := DecodeHeader(buffer.Bytes(), bobPrivKeyId, bobPrivKeyEp, nil, nil)
	assert.Equal(t, []byte("hallo"), m.PayloadRaw)
}

func TestDecodeInitReply(t *testing.T) {
	// Create a byte slice with the encoded message
	alicePrivKeyId, _ := ecdh.X25519().GenerateKey(rand.Reader)
	alicePubKeyId := alicePrivKeyId.PublicKey()
	slog.Debug("alicePubKeyId", slog.Any("alicePubKeyId", alicePubKeyId))
	bobPrivKeyId, _ := ecdh.X25519().GenerateKey(rand.Reader)
	bobPubKeyId := bobPrivKeyId.PublicKey()
	slog.Debug("bobPubKeyId", slog.Any("bobPubKeyId", bobPubKeyId))
	slog.Debug("bobPrivKeyId", slog.Any("bobPrivKeyId", bobPrivKeyId))

	alicePrivKeyEp, _ := ecdh.X25519().GenerateKey(rand.Reader)
	slog.Debug("alicePrivKeyEp", slog.Any("alicePrivKeyEp", alicePrivKeyEp))
	alicePubKeyEp := alicePrivKeyEp.PublicKey()
	slog.Debug("alicePubKeyEp", slog.Any("alicePubKeyEp", alicePrivKeyEp))
	bobPrivKeyEp, _ := ecdh.X25519().GenerateKey(rand.Reader)
	slog.Debug("bobPrivKeyEp", slog.Any("bobPrivKeyEp", bobPrivKeyEp))
	slog.Debug("bobPrivKeyEpPublicKey", slog.Any("bobPrivKeyEpPublicKey", bobPrivKeyEp.PublicKey()))

	secret2, _ := alicePrivKeyEp.ECDH(bobPubKeyId)
	secret1, _ := bobPrivKeyId.ECDH(alicePubKeyEp)

	slog.Debug("correct", slog.Any("s1", secret1))
	slog.Debug("correct", slog.Any("s2", secret2))

	slog.Debug("pubKeyEpSnd", slog.Any("pubKeyEpSnd1", bobPubKeyId))
	slog.Debug("pubKeyEpSnd", slog.Any("pubKeyEpSnd2", bobPubKeyId))
	slog.Debug("privKeyEpRcv", slog.Any("privKeyEpRcv", alicePrivKeyEp))

	slog.Debug("pubKeyEpSnd", slog.Any("pubKeyEpSnd", alicePubKeyEp))
	slog.Debug("privKeyEpRcv", slog.Any("privKeyEpRcv", bobPrivKeyId))

	var bufferInit bytes.Buffer
	//Alice (snd) -> Bob (rcv)
	n, _ := EncodeWriteInit(bobPubKeyId, alicePubKeyId, alicePrivKeyEp, 77, []byte("hallo"), &bufferInit)
	m, _ := DecodeHeader(bufferInit.Bytes(), bobPrivKeyId, bobPrivKeyEp, nil, nil)

	var bufferInitReply bytes.Buffer
	// Bob (snd) -> Alice (rcv)
	n, _ = EncodeWriteInitReply(alicePubKeyId, bobPrivKeyId, bobPrivKeyEp, m.SharedSecret, 77, []byte("2hallo12"), &bufferInitReply)
	testErrorMac(t, bufferInitReply.Bytes(), n, nil, alicePrivKeyEp, bobPubKeyId, nil)
	testErrorContent(t, bufferInitReply.Bytes(), n, nil, alicePrivKeyEp, bobPubKeyId, nil)
	testErrorSize(t, bufferInitReply.Bytes(), n, nil, alicePrivKeyEp, bobPubKeyId, nil)
	testEmpty(t, bufferInitReply.Bytes(), n, nil, alicePrivKeyEp, bobPubKeyId, nil)
	m2, _ := DecodeHeader(bufferInitReply.Bytes(), nil, alicePrivKeyEp, bobPubKeyId, nil)
	assert.Equal(t, []byte("2hallo12"), m2.PayloadRaw)
	fmt.Printf("%v", n)

	//init has non prefect forward secrecy secret, reply has perfect
	assert.Equal(t, m.SharedSecret, m2.SharedSecret)
}

func TestDecodeMsg(t *testing.T) {
	// Create a byte slice with the encoded message
	alicePrivKeyId, _ := ecdh.X25519().GenerateKey(rand.Reader)
	alicePubKeyId := alicePrivKeyId.PublicKey()
	bobPrivKeyId, _ := ecdh.X25519().GenerateKey(rand.Reader)
	bobPubKeyId := bobPrivKeyId.PublicKey()

	alicePrivKeyEp, _ := ecdh.X25519().GenerateKey(rand.Reader)
	bobPrivKeyEp, _ := ecdh.X25519().GenerateKey(rand.Reader)

	var bufferInit bytes.Buffer
	// Alice (snd) -> Bob (rcv)
	n, _ := EncodeWriteInit(bobPubKeyId, alicePubKeyId, alicePrivKeyEp, 77, []byte("hallo"), &bufferInit)
	m, _ := DecodeHeader(bufferInit.Bytes(), bobPrivKeyId, bobPrivKeyEp, nil, nil)

	var bufferInitReply bytes.Buffer
	// Bob (snd) -> Alice (rcv)
	n, _ = EncodeWriteInitReply(alicePubKeyId, bobPrivKeyId, bobPrivKeyEp, m.SharedSecret, 77, []byte("2hallo12"), &bufferInitReply)
	m, _ = DecodeHeader(bufferInitReply.Bytes(), nil, alicePrivKeyEp, bobPubKeyId, []byte{})
	assert.Equal(t, []byte("2hallo12"), m.PayloadRaw)

	sharedSecret := m.SharedSecret
	var bufferMsg1 bytes.Buffer
	// Alice (snd) -> Bob (rcv)
	n, _ = EncodeWriteMsg(true, bobPubKeyId, alicePubKeyId, sharedSecret, 77, []byte("33hallo1"), &bufferMsg1)
	testErrorMac(t, bufferMsg1.Bytes(), n, nil, nil, nil, sharedSecret)
	testErrorContent(t, bufferMsg1.Bytes(), n, nil, nil, nil, sharedSecret)
	testErrorSize(t, bufferMsg1.Bytes(), n, nil, nil, nil, sharedSecret)
	testEmpty(t, bufferMsg1.Bytes(), n, nil, nil, nil, sharedSecret)
	m, _ = DecodeHeader(bufferMsg1.Bytes(), nil, nil, nil, sharedSecret)
	assert.Equal(t, []byte("33hallo1"), m.PayloadRaw)

	var bufferMsg2 bytes.Buffer
	// Bob (snd) -> Alice (rcv)
	n, _ = EncodeWriteMsg(true, alicePubKeyId, bobPubKeyId, sharedSecret, 77, []byte("33hallo1"), &bufferMsg2)
	testErrorMac(t, bufferMsg2.Bytes(), n, nil, nil, nil, sharedSecret)
	testErrorContent(t, bufferMsg2.Bytes(), n, nil, nil, nil, sharedSecret)
	testErrorSize(t, bufferMsg2.Bytes(), n, nil, nil, nil, sharedSecret)
	testEmpty(t, bufferMsg2.Bytes(), n, nil, nil, nil, sharedSecret)
	m, _ = DecodeHeader(bufferMsg2.Bytes(), nil, nil, nil, sharedSecret)
	assert.Equal(t, []byte("33hallo1"), m.PayloadRaw)
}

func testErrorMac(t *testing.T, b []byte, n int, privKeyIdRcv *ecdh.PrivateKey, privKeyEpRcv *ecdh.PrivateKey, pubKeyIdRcv *ecdh.PublicKey, sharedSecret []byte) {
	b2 := make([]byte, len(b))
	copy(b2, b)
	b2[len(b)-1] = b2[len(b)-1] + 1
	_, err := DecodeHeader(b2, privKeyIdRcv, privKeyEpRcv, pubKeyIdRcv, sharedSecret)
	assert.NotNil(t, err)
}

func testErrorContent(t *testing.T, b []byte, n int, privKeyIdRcv *ecdh.PrivateKey, privKeyEpRcv *ecdh.PrivateKey, pubKeyIdRcv *ecdh.PublicKey, sharedSecret []byte) {
	b2 := make([]byte, len(b))
	copy(b2, b)
	b2[len(b)-17] = b2[len(b)-17] + 1
	_, err := DecodeHeader(b2, privKeyIdRcv, privKeyEpRcv, pubKeyIdRcv, sharedSecret)
	assert.NotNil(t, err)
}

func testErrorSize(t *testing.T, b []byte, n int, privKeyIdRcv *ecdh.PrivateKey, privKeyEpRcv *ecdh.PrivateKey, pubKeyIdRcv *ecdh.PublicKey, sharedSecret []byte) {
	b2 := make([]byte, len(b)-1)
	copy(b2, b)
	_, err := DecodeHeader(b2, privKeyIdRcv, privKeyEpRcv, pubKeyIdRcv, sharedSecret)
	assert.NotNil(t, err)
}

func testEmpty(t *testing.T, b []byte, n int, privKeyIdRcv *ecdh.PrivateKey, privKeyEpRcv *ecdh.PrivateKey, pubKeyIdRcv *ecdh.PublicKey, sharedSecret []byte) {
	b2 := make([]byte, 0)
	_, err := DecodeHeader(b2, privKeyIdRcv, privKeyEpRcv, pubKeyIdRcv, sharedSecret)
	assert.NotNil(t, err)
}

func FuzzEncodeDecodeCrypto(f *testing.F) {
	// Generate initial seeds for the fuzzer
	f.Add([]byte("initial data for fuzzer"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Generate random keys for testing
		privKeyRcv, err := ecdh.X25519().GenerateKey(rand.Reader)
		pubKeyRcv := privKeyRcv.PublicKey()
		if err != nil {
			t.Fatalf("Failed to generate receiver keys: %v", err)
		}

		privKeySnd, err := ecdh.X25519().GenerateKey(rand.Reader)
		pubKeySnd := privKeySnd.PublicKey()
		if err != nil {
			t.Fatalf("Failed to generate sender keys: %v", err)
		}

		privKeyEp, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ephemeral keys: %v", err)
		}

		// Create a buffer to write the encoded message
		var buf bytes.Buffer

		// Encode an INIT message
		_, err = EncodeWriteInit(pubKeyRcv, pubKeySnd, privKeyEp, 77, data, &buf)
		if err != nil {
			// If encoding fails, just return (the input may be invalid)
			return
		}

		// Create a shared secret for MSG encoding
		sharedSecret := make([]byte, 32)
		if _, err := rand.Read(sharedSecret); err != nil {
			t.Fatalf("Failed to generate shared secret: %v", err)
		}

		// Encode an INIT_REPLY message
		_, err = EncodeWriteInitReply(pubKeyRcv, privKeySnd, privKeyEp, sharedSecret, 77, data, &buf)
		if err != nil {
			// If encoding fails, just return (the input may be invalid)
			return
		}

		// Encode a MSG message
		_, err = EncodeWriteMsg(true, pubKeyRcv, pubKeySnd, sharedSecret, 77, data, &buf)
		if err != nil {
			// If encoding fails, just return (the input may be invalid)
			return
		}

		// Now attempt to decode the generated message
		decodedMessage, err := DecodeHeader(buf.Bytes(), privKeyRcv, privKeyEp, pubKeyRcv, sharedSecret)
		if err != nil {
			// If decoding fails, log the error but don't necessarily fail the test
			t.Logf("Decoding failed: %v", err)
			return
		}

		// Perform additional checks on the decoded message, if necessary
		if decodedMessage == nil {
			t.Fatalf("Decoded message is nil")
		}

		if !bytes.Equal(decodedMessage.PayloadRaw, data) {
			t.Fatalf("Decoded message is different")
		}
	})
}

// Helper function to generate random data
func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}
