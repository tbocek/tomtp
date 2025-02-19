package tomtp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDoubleEncryptDecrypt(t *testing.T) {
	testCases := []struct {
		name           string
		sn             uint64
		data           []byte
		additionalData []byte
	}{
		{"Short Data", 1234567890, randomBytes(10), []byte("AAD")},
		{"Long Data", 987654321, randomBytes(100), randomBytes(100)},
		{"Long Data/Short", 1, randomBytes(100), []byte("")},
		{"Min Data", 2, randomBytes(9), []byte("Only AAD")},
		{"Min Data 2", 2, randomBytes(9), []byte("")},
		{"Empty Data", 1111111111, []byte{}, []byte("Only AAD")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sharedSecret := make([]byte, 32)
			if _, err := rand.Read(sharedSecret); err != nil {
				t.Fatalf("Failed to generate shared secret: %v", err)
			}

			buf, err := chainedEncrypt(tc.sn, true, sharedSecret, tc.additionalData, tc.data)
			//too short
			if len(tc.data) < MinPayloadSize {
				assert.NotNil(t, err)
				return
			}
			assert.Nil(t, err)

			if len(buf) == 0 {
				t.Fatalf("No encrypted dataToSend written")
			}
			t.Logf("Encrypted dataToSend: %s", hex.EncodeToString(buf))

			decryptedSn, decryptedData, err := chainedDecrypt(false, sharedSecret, buf[0:len(tc.additionalData)], buf[len(tc.additionalData):])
			assert.Nil(t, err)

			assert.Equal(t, tc.sn, decryptedSn)
			assert.Equal(t, tc.data, decryptedData)
		})
	}
}

func TestSecretKey(t *testing.T) {
	bobPrvKeyId, err := ecdh.X25519().GenerateKey(rand.Reader)
	assert.Nil(t, err)
	bobPubKeyId := bobPrvKeyId.PublicKey()
	alicePrvKeyEp, err := ecdh.X25519().GenerateKey(rand.Reader)
	assert.Nil(t, err)
	alicePubKeyEp := alicePrvKeyEp.PublicKey()

	secret1, err := bobPrvKeyId.ECDH(alicePubKeyEp)
	assert.Nil(t, err)
	secret2, err := alicePrvKeyEp.ECDH(bobPubKeyId)
	assert.Nil(t, err)

	assert.Equal(t, secret1, secret2)
}

func TestEncodeDecodeInitS0(t *testing.T) {
	testCases := []struct {
		name     string
		payload  []byte
		expected []byte
	}{
		{"Short PayloadMeta", []byte("short1234"), nil},
		{"Long PayloadMeta", randomBytes(100), nil},
		{"Max PayloadMeta", randomBytes(1400), nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			alicePrvKeyId, alicePrvKeyEp, err := generateTwoKeys()
			assert.NoError(t, err)
			alicePrvKeyEpRollover := generateKeys(t)
			bobPrvKeyId, _, err := generateTwoKeys()
			assert.NoError(t, err)

			buffer, err := EncodeInitWithCryptoS0(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), alicePrvKeyEp, alicePrvKeyEpRollover, tc.payload)
			assert.Nil(t, err)

			_, _, _, m, err := DecodeInitWithCryptoS0(buffer, bobPrvKeyId, alicePrvKeyEp)
			assert.Nil(t, err)
			assert.Equal(t, tc.payload, m.PayloadRaw)
		})
	}
}

func TestEncodeDecodeInitR0(t *testing.T) {
	testCases := []struct {
		name     string
		payload  []byte
		expected []byte
	}{
		{"Short PayloadMeta", []byte("short1234"), nil},
		{"Long PayloadMeta", randomBytes(100), nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			alicePrvKeyId, alicePrvKeyEp, err := generateTwoKeys()
			assert.NoError(t, err)
			alicePrvKeyEpRollover := generateKeys(t)
			bobPrvKeyId, bobPrvKeyEp, err := generateTwoKeys()
			assert.NoError(t, err)
			bobPrvKeyEpRollover := generateKeys(t)

			//Alice -> Bob, Alice encodes
			bufferInit, err := EncodeInitWithCryptoS0(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), alicePrvKeyEp, alicePrvKeyEpRollover, tc.payload)
			assert.Nil(t, err)

			//Bob decodes message from Alice
			_, _, _, m, err := DecodeInitWithCryptoS0(bufferInit, bobPrvKeyId, bobPrvKeyEp)
			assert.Nil(t, err)

			//Bob -> Alice
			bufferInitReply, err := EncodeInitWithCryptoR0(alicePrvKeyId.PublicKey(), bobPrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), bobPrvKeyEp, bobPrvKeyEpRollover, tc.payload)
			assert.Nil(t, err)

			//Alice decodes message from Bob
			_, _, m2, err := DecodeInitWithCryptoR0(bufferInitReply, alicePrvKeyEp)
			assert.Nil(t, err)
			assert.Equal(t, tc.payload, m2.PayloadRaw)

			assert.Equal(t, m.SharedSecret, m2.SharedSecret)
		})
	}
}

func TestEncodeDecodeData0AndData(t *testing.T) {
	testCases := []struct {
		name     string
		payload  []byte
		expected []byte
	}{
		{"Short PayloadMeta", []byte("short1234"), nil},
		{"Long PayloadMeta", randomBytes(100), nil},
		{"Max PayloadMeta", randomBytes(1400), nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			alicePrvKeyId, _, err := generateTwoKeys()
			assert.NoError(t, err)
			alicePrvKeyEpRollover := generateKeys(t)
			bobPrvKeyId, bobPrvKeyEp, err := generateTwoKeys()
			assert.NoError(t, err)

			// Alice -> Bob
			bufferData0, err := EncodeData0(
				bobPrvKeyId.PublicKey(),
				alicePrvKeyId.PublicKey(),
				true,
				bobPrvKeyEp.PublicKey(),
				alicePrvKeyEpRollover,
				tc.payload)
			assert.Nil(t, err)

			// Bob decodes message from Alice
			_, m3, err := DecodeData0(bufferData0, false, bobPrvKeyEp)
			assert.Nil(t, err)
			assert.Equal(t, tc.payload, m3.PayloadRaw)

			// Then test regular DATA messages
			sharedSecret := m3.SharedSecret
			bufferData, err := EncodeData(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), true, sharedSecret, 1, tc.payload)
			assert.Nil(t, err)

			m4, err := DecodeData(bufferData, false, sharedSecret)
			assert.Nil(t, err)
			assert.Equal(t, tc.payload, m4.PayloadRaw)

			bufferData2, err := EncodeData(alicePrvKeyId.PublicKey(), bobPrvKeyId.PublicKey(), false, sharedSecret, 2, tc.payload)
			assert.Nil(t, err)

			m5, err := DecodeData(bufferData2, true, sharedSecret)
			assert.Nil(t, err)
			assert.Equal(t, tc.payload, m5.PayloadRaw)
		})
	}
}

func FuzzEncodeDecodeCrypto(f *testing.F) {
	// Add seed corpus with various sizes including invalid ones
	seeds := [][]byte{
		[]byte("initial dataToSend for fuzzer"),
		[]byte("1234567"),   // 7 bytes - should fail
		[]byte("12345678"),  // 8 bytes - minimum valid Size
		[]byte("123456789"), // 9 bytes - valid
		make([]byte, 7),     // 7 zero bytes - should fail
		make([]byte, 8),     // 8 zero bytes - minimum valid Size
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// First verify dataToSend Size requirements
		if len(data) < MinPayloadSize {
			// For dataToSend less than minimum Size, verify that we Get appropriate error
			alicePrvKeyId, alicePrvKeyEp, err := generateTwoKeys()
			assert.NoError(t, err)
			alicePrvKeyEpRollover := generateKeys(t)
			bobPrvKeyId, _, err := generateTwoKeys()
			assert.NoError(t, err)

			// Try InitSnd - should fail
			_, err = EncodeInitWithCryptoS0(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), alicePrvKeyEp, alicePrvKeyEpRollover, data)
			assert.Error(t, err, "Expected error for dataToSend Size %d < %d", len(data), MinPayloadSize)
			assert.Equal(t, "packet dataToSend too short", err.Error(), "Wrong error message for small dataToSend")
			return
		}

		// For valid sizes, proceed with full testing
		alicePrvKeyId, alicePrvKeyEp, err := generateTwoKeys()
		assert.NoError(t, err)
		alicePrvKeyEpRollover := generateKeys(t)
		bobPrvKeyId, bobPrvKeyEp, err := generateTwoKeys()
		assert.NoError(t, err)
		bobPrvKeyEpRollover := generateKeys(t)

		// Alice -> Bob
		bufferInit, err := EncodeInitWithCryptoS0(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), alicePrvKeyEp, alicePrvKeyEpRollover, data)
		assert.NoError(t, err)

		// Bob decodes
		_, _, _, initDecoded, err := DecodeInitWithCryptoS0(bufferInit, bobPrvKeyId, alicePrvKeyEp)
		assert.NoError(t, err)
		assert.True(t, bytes.Equal(initDecoded.PayloadRaw, data),
			"InitSnd payload mismatch: got %v, want %v", initDecoded.PayloadRaw, data)

		// Bob -> Alice
		bufferInitReply, err := EncodeInitWithCryptoR0(alicePrvKeyId.PublicKey(), bobPrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), bobPrvKeyEp, bobPrvKeyEpRollover, data)
		assert.NoError(t, err)

		// Alice decodes
		_, _, decodedInitReply, err := DecodeInitWithCryptoR0(bufferInitReply, alicePrvKeyEp)
		assert.NoError(t, err)
		assert.True(t, bytes.Equal(decodedInitReply.PayloadRaw, data),
			"InitRcv payload mismatch: got %v, want %v", decodedInitReply.PayloadRaw, data)

		// Alice -> Bob
		bufferData0, err := EncodeData0(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), true, bobPrvKeyEp.PublicKey(), alicePrvKeyEpRollover, data)
		assert.NoError(t, err)

		// Bob decodes rollover
		_, decodedData0Msg, err := DecodeData0(bufferData0, false, bobPrvKeyEp)
		assert.NoError(t, err)
		assert.True(t, bytes.Equal(decodedData0Msg.PayloadRaw, data),
			"Data0 message payload mismatch: got %v, want %v", decodedData0Msg.PayloadRaw, data)

		// Alice -> Bob
		sharedSecret := decodedData0Msg.SharedSecret
		bufferData, err := EncodeData(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), true, sharedSecret, 1, data)
		assert.NoError(t, err)

		// Bob decodes
		decodedDataMsg, err := DecodeData(bufferData, false, sharedSecret)
		assert.NoError(t, err)
		assert.True(t, bytes.Equal(decodedDataMsg.PayloadRaw, data),
			"Data message payload mismatch: got %v, want %v", decodedDataMsg.PayloadRaw, data)
	})
}

func TestEncodeDecodeInitHandshake(t *testing.T) {
	t.Run("S0 basic flow", func(t *testing.T) {
		// Generate keys
		alicePrvKeyId, alicePrvKeyEp, err := generateTwoKeys()
		assert.NoError(t, err)
		alicePrvKeyEpRollover := generateKeys(t)
		bobPrvKeyEp := generateKeys(t)

		// Alice -> Bob: Encode InitHandshakeS0
		buffer := EncodeInitHandshakeS0(
			alicePrvKeyId.PublicKey(),
			alicePrvKeyEp,
			alicePrvKeyEpRollover, 1)

		// Bob receives and decodes InitHandshakeS0
		pubKeyIdSnd, pubKeyEpSnd, pubKeyEpSndRollover, msg, err := DecodeInitHandshakeS0(
			buffer,
			bobPrvKeyEp)

		// Verify the results
		assert.NoError(t, err)
		assert.Equal(t, InitHandshakeS0MsgType, msg.MsgType)
		assert.Equal(t, uint64(0), msg.SnConn)
		assert.NotNil(t, msg.SharedSecret)

		// Verify the public keys match what was sent
		assert.True(t, bytes.Equal(alicePrvKeyId.PublicKey().Bytes(), pubKeyIdSnd.Bytes()))
		assert.True(t, bytes.Equal(alicePrvKeyEp.PublicKey().Bytes(), pubKeyEpSnd.Bytes()))
		assert.True(t, bytes.Equal(alicePrvKeyEpRollover.PublicKey().Bytes(), pubKeyEpSndRollover.Bytes()))
	})

	t.Run("S0 invalid size", func(t *testing.T) {
		// Test with buffer that's too small
		buffer := make([]byte, MsgInitHandshakeS0Size-1)
		_, _, _, _, err := DecodeInitHandshakeS0(buffer, generateKeys(t))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "size is below minimum init")
	})

	t.Run("R0 basic flow", func(t *testing.T) {
		// Generate keys
		alicePrvKeyId, alicePrvKeyEp, err := generateTwoKeys()
		assert.NoError(t, err)
		//alicePrvKeyEpRollover := generateKeys(t)
		bobPrvKeyId, bobPrvKeyEp, err := generateTwoKeys()
		assert.NoError(t, err)
		bobPrvKeyEpRollover := generateKeys(t)

		// Bob -> Alice: Encode InitHandshakeR0
		rawData := []byte("test data")
		buffer, err := EncodeInitHandshakeR0(
			alicePrvKeyId.PublicKey(),
			bobPrvKeyId.PublicKey(),
			alicePrvKeyEp.PublicKey(),
			bobPrvKeyEp,
			bobPrvKeyEpRollover, 1,
			rawData)

		assert.NoError(t, err)

		// Alice receives and decodes InitHandshakeR0
		pubKeyIdRcv, pubKeyEpRcv, pubKeyEpRcvRollover, msg, err := DecodeInitHandshakeR0(
			buffer,
			alicePrvKeyEp)

		// Verify the results
		assert.NoError(t, err)
		assert.Equal(t, InitHandshakeR0MsgType, msg.MsgType)
		assert.Equal(t, uint64(0), msg.SnConn)
		assert.Equal(t, rawData, msg.PayloadRaw)
		assert.NotNil(t, msg.SharedSecret)

		// Verify the public keys match what was sent
		assert.True(t, bytes.Equal(bobPrvKeyId.PublicKey().Bytes(), pubKeyIdRcv.Bytes()))
		assert.True(t, bytes.Equal(bobPrvKeyEp.PublicKey().Bytes(), pubKeyEpRcv.Bytes()))
		assert.True(t, bytes.Equal(bobPrvKeyEpRollover.PublicKey().Bytes(), pubKeyEpRcvRollover.Bytes()))
	})

	t.Run("R0 invalid size", func(t *testing.T) {
		// Test with buffer that's too small
		buffer := make([]byte, MsgInitHandshakeR0Size-1)
		_, _, _, _, err := DecodeInitHandshakeR0(buffer, generateKeys(t))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "size is below minimum init reply")
	})

	t.Run("full handshake flow", func(t *testing.T) {
		// Generate keys for both parties
		alicePrvKeyId, alicePrvKeyEp, err := generateTwoKeys()
		assert.NoError(t, err)
		alicePrvKeyEpRollover := generateKeys(t)
		bobPrvKeyId, bobPrvKeyEp, err := generateTwoKeys()
		assert.NoError(t, err)
		bobPrvKeyEpRollover := generateKeys(t)

		// Step 1: Alice sends InitHandshakeS0
		bufferS0 := EncodeInitHandshakeS0(
			alicePrvKeyId.PublicKey(),
			alicePrvKeyEp,
			alicePrvKeyEpRollover, 1)

		// Step 2: Bob receives and decodes InitHandshakeS0
		_, _, _, msgS0, err := DecodeInitHandshakeS0(
			bufferS0,
			bobPrvKeyEp)
		assert.NoError(t, err)

		// Step 3: Bob sends InitHandshakeR0
		rawData := []byte("handshake response")
		bufferR0, err := EncodeInitHandshakeR0(
			alicePrvKeyId.PublicKey(),
			bobPrvKeyId.PublicKey(),
			alicePrvKeyEp.PublicKey(),
			bobPrvKeyEp,
			bobPrvKeyEpRollover, 1,
			rawData)
		assert.NoError(t, err)

		// Step 4: Alice receives and decodes InitHandshakeR0
		_, _, _, msgR0, err := DecodeInitHandshakeR0(
			bufferR0,
			alicePrvKeyEp)
		assert.NoError(t, err)

		// Verify shared secrets match
		assert.True(t, bytes.Equal(msgS0.SharedSecret, msgR0.SharedSecret))
	})

	t.Run("nil key handling", func(t *testing.T) {
		// Test encoding with nil keys
		assert.Panics(t, func() {
			EncodeInitHandshakeS0(nil, nil, nil, 1)
		})

		assert.Panics(t, func() {
			EncodeInitHandshakeR0(nil, nil, nil, nil, nil, 1, []byte("test"))
		})

		validBuffer := make([]byte, startMtu)
		assert.Panics(t, func() {
			DecodeInitHandshakeS0(validBuffer, nil)
		})

		validBuffer = make([]byte, startMtu)
		assert.Panics(t, func() {
			DecodeInitHandshakeR0(validBuffer, nil)
		})
	})
}

// Helper function to generate random dataToSend
func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func generateKeys(t *testing.T) *ecdh.PrivateKey {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	return privKey
}
