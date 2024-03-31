package tomtp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"filippo.io/edwards25519"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
)

type MsgType uint8

const (
	Init MsgType = iota
	InitReply
	Msg
	Na
)

type MessageHeader struct {
	Type             MsgType
	PubKeyIdRcvShort [4]byte
	PukKeyIdSnd      ed25519.PublicKey
	PukKeyIdSndShort [4]byte
}

type Message struct {
	MessageHeader
	PukKeyEpSnd  *ecdh.PublicKey
	Payload      *Payload
	Fill         []byte
	SharedSecret [32]byte
}

type Payload struct {
	StreamId      uint32
	EncryptedData []byte
}

// EncodeWriteInit encodes the message into a byte slice
func EncodeWriteInit(
	pubKeyIdRcv ed25519.PublicKey,
	pukKeyIdSnd ed25519.PublicKey,
	data []byte,
	epPrivKeyCurve *ecdh.PrivateKey,
	wr io.Writer) (n int, err error) {
	// Write the public key
	var buffer bytes.Buffer
	w := &buffer

	//magic, version, and type
	const versionValue uint8 = 0
	header := (versionValue << 2) | uint8(Init)
	if err := w.WriteByte(header); err != nil {
		return 0, err
	}

	// first 32bit of the public key of the id of the receiver
	if _, err := w.Write(pubKeyIdRcv[0:4]); err != nil {
		return 0, err
	}

	// our full public key
	if _, err := w.Write(pukKeyIdSnd); err != nil {
		return 0, err
	}

	// ephemeral keys
	if _, err := w.Write(epPrivKeyCurve.PublicKey().Bytes()); err != nil {
		return 0, err
	}

	nonce, err := generateRandomNonce(24)
	if err != nil {
		return 0, err
	}
	// create and write nonce (192bit = 24byte Nonce)
	if _, err := w.Write(nonce[:]); err != nil {
		return 0, err
	}

	pubKeyIdRcvCurve, err := ed25519PublicKeyToCurve25519(pubKeyIdRcv)
	if err != nil {
		return 0, err
	}
	secret, err := epPrivKeyCurve.ECDH(pubKeyIdRcvCurve)
	if err != nil {
		return 0, err
	}
	sharedSecret := sha256.Sum256(secret)

	aead, err := chacha20poly1305.NewX(sharedSecret[:])
	if err != nil {
		return 0, err
	}

	encData := aead.Seal(nil, nonce[:], data, buffer.Bytes())
	if _, err := w.Write(encData); err != nil {
		return 0, err
	}

	return wr.Write(buffer.Bytes())
}

func Decode(b []byte, n int, privKeyIdRcv ed25519.PrivateKey, sharedSecret [32]byte) (*Message, error) {
	buf := bytes.NewBuffer(b)

	// Read the header byte
	header, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}

	var mh MessageHeader

	// Extract the version, and message type from the header
	versionValue := (header >> 2) & 0x3f
	messageType := header & 0x03

	if versionValue != 0 {
		return nil, errors.New("invalid version")
	}
	mh.Type = MsgType(messageType)

	var pubKeyIdRcv [4]byte
	if _, err := io.ReadFull(buf, pubKeyIdRcv[:]); err != nil {
		return nil, err
	}
	mh.PubKeyIdRcvShort = pubKeyIdRcv

	if messageType == uint8(Init) {
		var pukKeyIdSnd [32]byte
		if _, err := io.ReadFull(buf, pukKeyIdSnd[:]); err != nil {
			return nil, err
		}
		mh.PukKeyIdSnd = pukKeyIdSnd[:]
		copy(mh.PukKeyIdSndShort[:], pukKeyIdSnd[:4])
	} else {
		var pukKeyIdSnd [4]byte
		if _, err := io.ReadFull(buf, pukKeyIdSnd[:]); err != nil {
			return nil, err
		}
		mh.PukKeyIdSndShort = pukKeyIdSnd
	}

	if messageType == uint8(Init) {
		//new stream, check if no old stream, otherwise reset old stream
		//store secret
		return DecodeInit(buf, n, privKeyIdRcv, mh)
	} else if messageType == uint8(InitReply) {
		//get stream, get secret
		return DecodeInitReply(buf, n, sharedSecret, mh)
	} else if messageType == uint8(Msg) {
		//get stream, get secret
		return DecodeMsg(buf, n, sharedSecret, mh)
	} else {
		return nil, errors.New("Unused message type")
	}

}

// DecodeInit decodes the message from a byte slice
func DecodeInit(buf *bytes.Buffer, n int, privKeyIdRcv ed25519.PrivateKey, mh MessageHeader) (*Message, error) {
	// Read the ephemeral public key
	epPubKeyBytes := make([]byte, 32)
	if _, err := io.ReadFull(buf, epPubKeyBytes); err != nil {
		return nil, err
	}
	epPubKey, err := ecdh.X25519().NewPublicKey(epPubKeyBytes)
	if err != nil {
		return nil, err
	}

	// Read the nonce
	var nonce [24]byte
	if _, err := io.ReadFull(buf, nonce[:]); err != nil {
		return nil, err
	}

	// Calculate the shared secret
	privKeyIdRcvCurve := ed25519PrivateKeyToCurve25519(privKeyIdRcv)
	secret, err := privKeyIdRcvCurve.ECDH(epPubKey)
	if err != nil {
		return nil, err
	}
	sharedSecret := sha256.Sum256(secret)

	// Initialize AEAD
	aead, err := chacha20poly1305.NewX(sharedSecret[:])
	if err != nil {
		return nil, err
	}
	// Read the rest of the data for decryption
	encryptedData := make([]byte, buf.Len())
	if _, err := io.ReadFull(buf, encryptedData); err != nil {
		return nil, err
	}

	// Decrypt the data
	buf.Reset()
	decryptedData, err := aead.Open(nil, nonce[:], encryptedData, buf.Bytes()[0:93])
	if err != nil {
		return nil, err
	}

	// Construct the InitMessage
	epPubKeyCurve, err := ecdh.X25519().NewPublicKey(epPubKeyBytes)
	if err != nil {
		return nil, err
	}
	m := &Message{
		MessageHeader: mh,
		PukKeyEpSnd:   epPubKeyCurve,
		Payload: &Payload{
			EncryptedData: decryptedData,
		},
		SharedSecret: sharedSecret,
	}
	return m, nil
}

// EncodeWriteInitReply encodes and writes an INIT_REPLY packet.
func EncodeWriteInitReply(
	pubKeyIdRcv ed25519.PublicKey,
	pukKeyIdSnd ed25519.PublicKey,
	epPubKeySnd ed25519.PublicKey,
	data []byte,
	sharedSecret [32]byte,
	wr io.Writer) (n int, err error) {

	var buffer bytes.Buffer
	w := &buffer

	// Construct the header with version and message type for INIT_REPLY
	const versionValue uint8 = 0
	header := (versionValue << 2) | uint8(InitReply)
	if err := w.WriteByte(header); err != nil {
		return 0, err
	}

	// Write the public key IDs and ephemeral public key
	if _, err := w.Write(pubKeyIdRcv[:4]); err != nil {
		return 0, err
	}
	if _, err := w.Write(pukKeyIdSnd[:4]); err != nil {
		return 0, err
	}
	if _, err := w.Write(epPubKeySnd[:]); err != nil {
		return 0, err
	}

	// Generate and write nonce
	nonce, err := generateRandomNonce(24)
	if err != nil {
		return 0, err
	}
	if _, err := w.Write(nonce[:]); err != nil {
		return 0, err
	}

	// Encrypt the payload
	aead, err := chacha20poly1305.NewX(sharedSecret[:])
	if err != nil {
		return 0, err
	}
	encData := aead.Seal(nil, nonce[:], data, buffer.Bytes())
	if _, err := w.Write(encData); err != nil {
		return 0, err
	}

	return wr.Write(buffer.Bytes())
}

// DecodeInitReply decodes an INIT_REPLY packet.
func DecodeInitReply(buf *bytes.Buffer, n int, sharedSecret [32]byte, mh MessageHeader) (*Message, error) {
	var epPubKeyBytes [32]byte
	if _, err := io.ReadFull(buf, epPubKeyBytes[:]); err != nil {
		return nil, err
	}
	epPubKeyCurve, err := ecdh.X25519().NewPublicKey(epPubKeyBytes[:])
	if err != nil {
		return nil, err
	}

	// Read nonce
	var nonce [24]byte
	if _, err := io.ReadFull(buf, nonce[:]); err != nil {
		return nil, err
	}

	// Decrypt the data
	aead, err := chacha20poly1305.NewX(sharedSecret[:])
	if err != nil {
		return nil, err
	}
	encryptedData := make([]byte, buf.Len()-16) // Exclude auth tag size from the total length
	if _, err := io.ReadFull(buf, encryptedData); err != nil {
		return nil, err
	}

	buf.Reset()
	decryptedData, err := aead.Open(nil, nonce[:], encryptedData, buf.Bytes()[0:65])
	if err != nil {
		return nil, err
	}

	// Construct the InitReplyMessage

	m := &Message{
		MessageHeader: mh,
		PukKeyEpSnd:   epPubKeyCurve,
		Payload: &Payload{
			EncryptedData: decryptedData,
		},
	}

	return m, nil
}

// EncodeWriteMsg encodes and writes a MSG packet.
func EncodeWriteMsg(
	pubKeyIdRcv ed25519.PublicKey,
	pukKeyIdSnd ed25519.PublicKey,
	data []byte,
	sharedSecret [32]byte,
	wr io.Writer) (n int, err error) {

	var buffer bytes.Buffer
	w := &buffer

	// Construct the header with version and message type for MSG
	const versionValue uint8 = 1 // Assuming version 1 for this example
	header := (versionValue << 2) | uint8(Msg)
	if err := w.WriteByte(header); err != nil {
		return 0, err
	}

	// Write the public key IDs
	if _, err := w.Write(pubKeyIdRcv[:4]); err != nil { // Assuming the first 32 bits are used
		return 0, err
	}
	if _, err := w.Write(pukKeyIdSnd[:4]); err != nil { // Assuming the first 32 bits are used
		return 0, err
	}

	// Generate and write nonce
	nonce, err := generateRandomNonce(24)
	if err != nil {
		return 0, err
	}
	if _, err := w.Write(nonce[:]); err != nil {
		return 0, err
	}

	// Encrypt the payload
	aead, err := chacha20poly1305.NewX(sharedSecret[:])
	if err != nil {
		return 0, err
	}
	encData := aead.Seal(nil, nonce[:], data, buffer.Bytes())
	if _, err := w.Write(encData); err != nil {
		return 0, err
	}

	return wr.Write(buffer.Bytes())
}

// DecodeMsg decodes a MSG packet.
func DecodeMsg(buf *bytes.Buffer, n int, sharedSecret [32]byte, mh MessageHeader) (*Message, error) {
	// Read nonce
	var nonce [24]byte
	if _, err := io.ReadFull(buf, nonce[:]); err != nil {
		return nil, err
	}

	// Initialize AEAD and decrypt the data
	aead, err := chacha20poly1305.NewX(sharedSecret[:])
	if err != nil {
		return nil, err
	}
	encryptedData := make([]byte, buf.Len())
	if _, err := io.ReadFull(buf, encryptedData); err != nil {
		return nil, err
	}

	buf.Reset()
	decryptedData, err := aead.Open(nil, nonce[:], encryptedData, buf.Bytes()[0:33])
	if err != nil {
		return nil, err
	}

	// Construct and return the message
	m := &Message{
		MessageHeader: mh,
		Payload: &Payload{
			EncryptedData: decryptedData,
		},
	}

	return m, nil
}

func generateRandomNonce(length int) ([24]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, err
	}
	return nonce, nil
}

// see https://hodo.dev/posts/post-48-ecdh-over-ed25519/
// see https://github.com/teserakt-io/golang-ed25519/blob/master/extra25519/extra25519.go
// source: https://github.com/FiloSottile/age/blob/980763a16e30ea5c285c271344d2202fcb18c33b/agessh/agessh.go#L287
// ed25519PrivateKeyToCurve25519 converts a ed25519 private key in X25519 equivalent
func ed25519PrivateKeyToCurve25519(privKey ed25519.PrivateKey) *ecdh.PrivateKey {
	h := sha512.New()
	h.Write(privKey.Seed())
	digest := h.Sum(nil)
	//no err, as we know that the size is 32
	privKeyCurve, _ := ecdh.X25519().NewPrivateKey(digest[:32])
	return privKeyCurve
}

// source: https://github.com/FiloSottile/age/blob/main/agessh/agessh.go#L190
// ed25519PublicKeyToCurve25519 converts a ed25519 public key in X25519 equivalent
func ed25519PublicKeyToCurve25519(pubKey ed25519.PublicKey) (*ecdh.PublicKey, error) {
	// See https://blog.filippo.io/using-ed25519-keys-for-encryption and
	// https://pkg.go.dev/filippo.io/edwards25519#Point.BytesMontgomery.
	p, err := new(edwards25519.Point).SetBytes(pubKey)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(p.BytesMontgomery())
}
