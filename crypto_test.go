package tomtp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
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
	var buf []byte

	// Call doubleEncrypt
	buf, err := chainedEncrypt(sn, sharedSecret, additionalData, data)
	if err != nil {
		t.Fatalf("doubleEncrypt failed: %v", err)
	}

	// Verify the encryption was successful
	if len(buf) == 0 {
		t.Fatalf("No encrypted data written")
	}
	t.Logf("Encrypted data: %s", hex.EncodeToString(buf))

	// Call doubleDecrypt
	decryptedSn, decryptedData, err := chainedDecrypt(sharedSecret, buf[0:len(additionalData)], buf[len(additionalData):])
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
	var buffer []byte
	//Alice (snd) sends to Bob (rcv)
	buffer, err := EncodeWriteInit(bobPubKeyId, alicePubKeyId, alicePrivKeyEp, []byte("12345678"))
	assert.Nil(t, err)
	//Bob (rcv) received the message from Alice (snd)

	h, c, err := decodeConnId(buffer)
	assert.Nil(t, err)
	m, err := Decode(InitSnd, buffer, h, c, bobPrivKeyId, bobPrivKeyEp, nil)
	assert.Nil(t, err)
	assert.Equal(t, []byte("12345678"), m.PayloadRaw)
}

func TestDecodeInitReply(t *testing.T) {
	// Create a byte slice with the encoded message
	alicePrivKeyId, err := ecdh.X25519().GenerateKey(rand.Reader)
	assert.Nil(t, err)
	alicePubKeyId := alicePrivKeyId.PublicKey()
	slog.Debug("alicePubKeyId", slog.Any("alicePubKeyId", alicePubKeyId))
	bobPrivKeyId, err := ecdh.X25519().GenerateKey(rand.Reader)
	assert.Nil(t, err)
	bobPubKeyId := bobPrivKeyId.PublicKey()
	slog.Debug("bobPubKeyId", slog.Any("bobPubKeyId", bobPubKeyId))
	slog.Debug("bobPrivKeyId", slog.Any("bobPrivKeyId", bobPrivKeyId))

	alicePrivKeyEp, err := ecdh.X25519().GenerateKey(rand.Reader)
	assert.Nil(t, err)
	slog.Debug("alicePrivKeyEp", slog.Any("alicePrivKeyEp", alicePrivKeyEp))
	alicePubKeyEp := alicePrivKeyEp.PublicKey()
	slog.Debug("alicePubKeyEp", slog.Any("alicePubKeyEp", alicePrivKeyEp))
	bobPrivKeyEp, err := ecdh.X25519().GenerateKey(rand.Reader)
	assert.Nil(t, err)
	slog.Debug("bobPrivKeyEp", slog.Any("bobPrivKeyEp", bobPrivKeyEp))
	slog.Debug("bobPrivKeyEpPublicKey", slog.Any("bobPrivKeyEpPublicKey", bobPrivKeyEp.PublicKey()))

	secret2, err := alicePrivKeyEp.ECDH(bobPubKeyId)
	assert.Nil(t, err)
	secret1, err := bobPrivKeyId.ECDH(alicePubKeyEp)
	assert.Nil(t, err)

	slog.Debug("correct", slog.Any("s1", secret1))
	slog.Debug("correct", slog.Any("s2", secret2))

	slog.Debug("pubKeyEpSnd", slog.Any("pubKeyEpSnd1", bobPubKeyId))
	slog.Debug("pubKeyEpSnd", slog.Any("pubKeyEpSnd2", bobPubKeyId))
	slog.Debug("privKeyEpRcv", slog.Any("privKeyEpRcv", alicePrivKeyEp))

	slog.Debug("pubKeyEpSnd", slog.Any("pubKeyEpSnd", alicePubKeyEp))
	slog.Debug("privKeyEpRcv", slog.Any("privKeyEpRcv", bobPrivKeyId))

	var bufferInit []byte
	//Alice (snd) -> Bob (rcv)
	bufferInit, err = EncodeWriteInit(bobPubKeyId, alicePubKeyId, alicePrivKeyEp, []byte("12345678"))
	assert.Nil(t, err)

	h, c, err := decodeConnId(bufferInit)
	assert.Nil(t, err)
	m, err := Decode(InitSnd, bufferInit, h, c, bobPrivKeyId, bobPrivKeyEp, nil)
	assert.Nil(t, err)

	var bufferInitReply []byte
	// Bob (snd) -> Alice (rcv)
	bufferInitReply, err = EncodeWriteInitReply(alicePubKeyId, bobPrivKeyId, alicePubKeyEp, bobPrivKeyEp, []byte("2hallo12"))
	assert.Nil(t, err)

	h, c, err = decodeConnId(bufferInitReply)
	assert.Nil(t, err)
	//Alice decodes
	m2, err := Decode(InitRcv, bufferInitReply, h, c, alicePrivKeyId, alicePrivKeyEp, nil)
	assert.Nil(t, err)
	assert.Equal(t, []byte("2hallo12"), m2.PayloadRaw)

	//init has non prefect forward secrecy secret, reply has perfect
	assert.Equal(t, m.SharedSecret, m2.SharedSecret)
}

func TestDecodeMsg(t *testing.T) {
	// Create a byte slice with the encoded message
	alicePrivKeyId, err := ecdh.X25519().GenerateKey(rand.Reader)
	assert.Nil(t, err)
	alicePubKeyId := alicePrivKeyId.PublicKey()
	bobPrivKeyId, err := ecdh.X25519().GenerateKey(rand.Reader)
	assert.Nil(t, err)
	bobPubKeyId := bobPrivKeyId.PublicKey()

	alicePrivKeyEp, err := ecdh.X25519().GenerateKey(rand.Reader)
	assert.Nil(t, err)
	alicePubKeyEp := alicePrivKeyEp.PublicKey()
	bobPrivKeyEp, err := ecdh.X25519().GenerateKey(rand.Reader)
	assert.Nil(t, err)

	var bufferInit []byte
	// Alice (snd) -> Bob (rcv)
	bufferInit, err = EncodeWriteInit(bobPubKeyId, alicePubKeyId, alicePrivKeyEp, []byte("12345678"))
	assert.Nil(t, err)

	h, c, err := decodeConnId(bufferInit)
	assert.Nil(t, err)
	m, err := Decode(InitSnd, bufferInit, h, c, bobPrivKeyId, bobPrivKeyEp, nil)
	assert.Nil(t, err)
	assert.NotNil(t, m)

	var bufferInitReply []byte
	// Bob (snd) -> Alice (rcv)
	bufferInitReply, err = EncodeWriteInitReply(alicePubKeyId, bobPrivKeyId, alicePubKeyEp, bobPrivKeyEp, []byte("2hallo12"))
	assert.Nil(t, err)

	h, c, err = decodeConnId(bufferInitReply)
	assert.Nil(t, err)
	//Alice decodes
	m2, err := Decode(InitRcv, bufferInitReply, h, c, alicePrivKeyId, alicePrivKeyEp, nil)
	assert.Nil(t, err)
	assert.Equal(t, []byte("2hallo12"), m2.PayloadRaw)

	sharedSecret := m2.SharedSecret
	var bufferMsg1 []byte
	// Alice (snd) -> Bob (rcv)
	bufferMsg1, err = EncodeWriteMsg(bobPubKeyId, alicePubKeyId, sharedSecret, 77, []byte("33hallo1"))
	assert.Nil(t, err)

	h, c, err = decodeConnId(bufferMsg1)
	assert.Nil(t, err)
	//Bob decodes
	m2, err = Decode(Msg, bufferMsg1, h, c, bobPrivKeyId, bobPrivKeyEp, sharedSecret)
	assert.Nil(t, err)
	assert.Equal(t, []byte("33hallo1"), m2.PayloadRaw)

	var bufferMsg2 []byte
	// Bob (snd) -> Alice (rcv)
	bufferMsg2, err = EncodeWriteMsg(alicePubKeyId, bobPubKeyId, sharedSecret, 77, []byte("33hallo1"))
	assert.Nil(t, err)

	h, c, err = decodeConnId(bufferMsg2)
	assert.Nil(t, err)
	// Alice decodes
	m2, err = Decode(Msg, bufferMsg2, h, c, alicePrivKeyId, alicePrivKeyEp, sharedSecret)
	assert.Nil(t, err)
	assert.Equal(t, []byte("33hallo1"), m2.PayloadRaw)
}

func FuzzEncodeDecodeCrypto(f *testing.F) {
	// Generte initial seeds for the fuzzer
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
		pubKeyEp := privKeyEp.PublicKey()
		if err != nil {
			t.Fatalf("Failed to generate ephemeral keys: %v", err)
		}

		// Create a buffer to write the encoded message
		var buf []byte

		// Encode an INIT message
		buf, err = EncodeWriteInit(pubKeyRcv, pubKeySnd, privKeyEp, data)
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
		buf, err = EncodeWriteInitReply(pubKeyRcv, privKeySnd, pubKeyEp, privKeyEp, data)
		if err != nil {
			// If encoding fails, just return (the input may be invalid)
			return
		}

		// Encode a MSG message
		buf, err = EncodeWriteMsg(pubKeyRcv, pubKeySnd, sharedSecret, 77, data)
		if err != nil {
			// If encoding fails, just return (the input may be invalid)
			return
		}

		// Now attempt to decode the generated message

		h, c, err := decodeConnId(buf)
		assert.Nil(t, err)
		decodedMessage, err := Decode(Msg, buf, h, c, privKeyRcv, privKeyEp, sharedSecret)
		assert.Nil(t, err)
		assert.NotNil(t, decodedMessage)

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
