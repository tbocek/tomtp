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
		{"Min Data", 2, randomBytes(8), []byte("Only AAD")},
		{"Min Data 2", 2, randomBytes(8), []byte("")},
		{"Empty Data", 1111111111, []byte{}, []byte("Only AAD")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sharedSecret := make([]byte, 32)
			if _, err := rand.Read(sharedSecret); err != nil {
				t.Fatalf("Failed to generate shared secret: %v", err)
			}

			buf, err := chainedEncrypt(tc.sn, sharedSecret, tc.additionalData, tc.data)
			//too short
			if len(tc.data) == 0 {
				assert.NotNil(t, err)
				return
			}
			assert.Nil(t, err)

			if len(buf) == 0 {
				t.Fatalf("No encrypted data written")
			}
			t.Logf("Encrypted data: %s", hex.EncodeToString(buf))

			decryptedSn, decryptedData, err := chainedDecrypt(sharedSecret, buf[0:len(tc.additionalData)], buf[len(tc.additionalData):])
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

func TestEncodeDecodeInitSnd(t *testing.T) {
	testCases := []struct {
		name     string
		payload  []byte
		expected []byte
	}{
		{"Short Payload", []byte("short123"), nil},
		{"Long Payload", randomBytes(100), nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			alicePrvKeyId, alicePrvKeyEp := generateTwoKeys(t)
			bobPrvKeyId, _ := generateTwoKeys(t)

			buffer, err := EncodeWriteInitSnd(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), alicePrvKeyEp, tc.payload)
			assert.Nil(t, err)

			m, err := Decode(InitSndMsgType, buffer, bobPrvKeyId, alicePrvKeyEp, nil)
			assert.Nil(t, err)
			assert.Equal(t, tc.payload, m.PayloadRaw)
		})
	}
}

func TestEncodeDecodeInitRcv(t *testing.T) {
	testCases := []struct {
		name     string
		payload  []byte
		expected []byte
	}{
		{"Short Payload", []byte("short123"), nil},
		{"Long Payload", randomBytes(100), nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			alicePrvKeyId, alicePrvKeyEp := generateTwoKeys(t)
			bobPrvKeyId, bobPrvKeyEp := generateTwoKeys(t)

			bufferInit, err := EncodeWriteInitSnd(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), alicePrvKeyEp, tc.payload)
			assert.Nil(t, err)

			m, err := Decode(InitSndMsgType, bufferInit, bobPrvKeyId, bobPrvKeyEp, nil)
			assert.Nil(t, err)

			bufferInitReply, err := EncodeWriteInitRcv(alicePrvKeyId.PublicKey(), bobPrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), bobPrvKeyEp, tc.payload)
			assert.Nil(t, err)

			m2, err := Decode(InitRcvMsgType, bufferInitReply, alicePrvKeyId, alicePrvKeyEp, nil)
			assert.Nil(t, err)
			assert.Equal(t, tc.payload, m2.PayloadRaw)

			assert.Equal(t, m.SharedSecret, m2.SharedSecret)
		})
	}
}

func TestEncodeDecodeDataMsg(t *testing.T) {
	testCases := []struct {
		name     string
		payload  []byte
		expected []byte
	}{
		{"Short Payload", []byte("short123"), nil},
		{"Long Payload", randomBytes(100), nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			alicePrvKeyId, alicePrvKeyEp := generateTwoKeys(t)
			bobPrvKeyId, bobPrvKeyEp := generateTwoKeys(t)

			bufferInit, err := EncodeWriteInitSnd(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), alicePrvKeyEp, tc.payload)
			assert.Nil(t, err)

			_, err = Decode(InitSndMsgType, bufferInit, bobPrvKeyId, bobPrvKeyEp, nil)
			assert.Nil(t, err)

			bufferInitReply, err := EncodeWriteInitRcv(alicePrvKeyId.PublicKey(), bobPrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), bobPrvKeyEp, tc.payload)
			assert.Nil(t, err)

			m2, err := Decode(InitRcvMsgType, bufferInitReply, alicePrvKeyId, alicePrvKeyEp, nil)
			assert.Nil(t, err)
			sharedSecret := m2.SharedSecret

			bufferData, err := EncodeWriteData(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), sharedSecret, 1, tc.payload)
			assert.Nil(t, err)

			m3, err := Decode(DataMsgType, bufferData, bobPrvKeyId, bobPrvKeyEp, sharedSecret)
			assert.Nil(t, err)
			assert.Equal(t, tc.payload, m3.PayloadRaw)

			bufferData2, err := EncodeWriteData(alicePrvKeyId.PublicKey(), bobPrvKeyId.PublicKey(), sharedSecret, 2, tc.payload)
			assert.Nil(t, err)

			m4, err := Decode(DataMsgType, bufferData2, alicePrvKeyId, alicePrvKeyEp, sharedSecret)
			assert.Nil(t, err)
			assert.Equal(t, tc.payload, m4.PayloadRaw)
		})
	}
}

func FuzzEncodeDecodeCrypto(f *testing.F) {
	// Add seed corpus with various sizes including invalid ones
	seeds := [][]byte{
		[]byte("initial data for fuzzer"),
		[]byte("1234567"),   // 7 bytes - should fail
		[]byte("12345678"),  // 8 bytes - minimum valid size
		[]byte("123456789"), // 9 bytes - valid
		make([]byte, 7),     // 7 zero bytes - should fail
		make([]byte, 8),     // 8 zero bytes - minimum valid size
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// First verify data size requirements
		if len(data) < MinPayloadSize {
			// For data less than minimum size, verify that we get appropriate error
			alicePrvKeyId, alicePrvKeyEp := generateTwoKeys(t)
			bobPrvKeyId, _ := generateTwoKeys(t)

			// Try InitSnd - should fail
			_, err := EncodeWriteInitSnd(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), alicePrvKeyEp, data)
			assert.Error(t, err, "Expected error for data size %d < %d", len(data), MinPayloadSize)
			assert.Equal(t, "data too short, need at least 8 bytes to make the double encryption work", err.Error(),
				"Wrong error message for small data")
			return
		}

		// For valid sizes, proceed with full testing
		alicePrvKeyId, alicePrvKeyEp := generateTwoKeys(t)
		bobPrvKeyId, bobPrvKeyEp := generateTwoKeys(t)

		// Test InitSnd
		bufferInit, err := EncodeWriteInitSnd(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), alicePrvKeyEp, data)
		assert.NoError(t, err)

		initDecoded, err := Decode(InitSndMsgType, bufferInit, bobPrvKeyId, alicePrvKeyEp, nil)
		assert.NoError(t, err)
		assert.True(t, bytes.Equal(initDecoded.PayloadRaw, data),
			"InitSnd payload mismatch: got %v, want %v", initDecoded.PayloadRaw, data)

		// Test InitRcv
		bufferInitReply, err := EncodeWriteInitRcv(alicePrvKeyId.PublicKey(), bobPrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), bobPrvKeyEp, data)
		assert.NoError(t, err)

		decodedInitReply, err := Decode(InitRcvMsgType, bufferInitReply, alicePrvKeyId, alicePrvKeyEp, nil)
		assert.NoError(t, err)
		assert.True(t, bytes.Equal(decodedInitReply.PayloadRaw, data),
			"InitRcv payload mismatch: got %v, want %v", decodedInitReply.PayloadRaw, data)

		// Test Data message
		sharedSecret := decodedInitReply.SharedSecret
		bufferData, err := EncodeWriteData(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), sharedSecret, 1, data)
		assert.NoError(t, err)

		decodedDataMsg, err := Decode(DataMsgType, bufferData, bobPrvKeyId, alicePrvKeyEp, sharedSecret)
		assert.NoError(t, err)
		assert.True(t, bytes.Equal(decodedDataMsg.PayloadRaw, data),
			"Data message payload mismatch: got %v, want %v", decodedDataMsg.PayloadRaw, data)
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

func generateKeys(t *testing.T) *ecdh.PrivateKey {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	return privKey
}

func generateTwoKeys(t *testing.T) (*ecdh.PrivateKey, *ecdh.PrivateKey) {
	prvKeyId := generateKeys(t)
	prvKeyEp := generateKeys(t)
	return prvKeyId, prvKeyEp
}
