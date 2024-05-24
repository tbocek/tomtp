package tomtp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"filippo.io/edwards25519"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"log/slog"
)

type MsgType uint8

const (
	Init MsgType = iota
	InitReply
	Msg
	Na

	MacSize = 16
	// MinMsgInitSize      [version 6bit | type 2bit | pubKeyIdShortRcv 32bit | pukKeyIdSnd 256bit] pukKeyEpSnd 256bit | nonce 192bit | [fill len 16bit | fill encrypted | payload encrypted] | mac 128bit
	MinMsgInitSize = 93 + MacSize
	// MinMsgInitReplySize [version 6bit | type 2bit | pubKeyIdShortRcv 32bit | pukKeyIdShortSnd 32bit] pukKeyEpSnd 256bit | nonce 192bit | [payload encrypted] | mac 128bit
	MinMsgInitReplySize = 65 + MacSize
	// MinMsgSize          [version 6bit | type 2bit | pubKeyIdShortRcv 32bit | pukKeyIdShortSnd 32bit] nonce 192bit | [payload encrypted] | mac 128bit
	MinMsgSize = 33 + MacSize
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
	PayloadRaw   []byte
	Payload      *Payload
	Fill         []byte
	SharedSecret []byte
}

// EncodeWriteInit encodes the message into a byte slice
func EncodeWriteInit(
	pubKeyIdRcv ed25519.PublicKey,
	pukKeyIdSnd ed25519.PublicKey,
	privKeyEpSnd *ecdh.PrivateKey,
	data []byte,
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
	if _, err := w.Write(privKeyEpSnd.PublicKey().Bytes()); err != nil {
		return 0, err
	}

	nonce, err := generateRandom24()
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
	secret, err := privKeyEpSnd.ECDH(pubKeyIdRcvCurve)
	if err != nil {
		return 0, err
	}
	sharedSecret := secret[:]

	aead, err := chacha20poly1305.NewX(sharedSecret[:])
	if err != nil {
		return 0, err
	}

	//prevent amplification attacks
	maxLenFill := uint16(startMtu - (MinMsgInitSize + len(data)))
	if maxLenFill > 0 {
		fillBytes := make([]byte, maxLenFill)
		fillBytes[0] = byte(maxLenFill >> 8)
		fillBytes[1] = byte(maxLenFill & 0xFF)
		data = append(fillBytes, data...)
	}

	encData := aead.Seal(nil, nonce[:], data, buffer.Bytes())
	if _, err := w.Write(encData); err != nil {
		return 0, err
	}

	n, err = wr.Write(buffer.Bytes())
	return n, err
}

// EncodeWriteInitReply encodes and writes an INIT_REPLY packet.
func EncodeWriteInitReply(
	pubKeyIdRcv ed25519.PublicKey,
	privKeyIdSnd ed25519.PrivateKey,
	pubKeyEpRcv *ecdh.PublicKey,
	privKeyEp *ecdh.PrivateKey,
	data []byte,
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
	if _, err := w.Write(privKeyIdSnd.Public().(ed25519.PublicKey)[:4]); err != nil {
		return 0, err
	}
	if _, err := w.Write(privKeyEp.PublicKey().Bytes()); err != nil {
		return 0, err
	}
	slog.Debug("deb", slog.Any("pub1", pubKeyEpRcv.Bytes()))
	slog.Debug("deb", slog.Any("pub2", privKeyEp.PublicKey().Bytes()))

	// Generate and write nonce
	nonce, err := generateRandom24()
	if err != nil {
		return 0, err
	}
	if _, err := w.Write(nonce[:]); err != nil {
		return 0, err
	}

	privKeyIdCurve := ed25519PrivateKeyToCurve25519(privKeyIdSnd)
	secret, err := privKeyIdCurve.ECDH(pubKeyEpRcv)
	if err != nil {
		return 0, err
	}
	sharedSecret := secret[:]
	slog.Debug("shareds2e", slog.Any("secret", secret))

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

// EncodeWriteMsg encodes and writes a MSG packet.
func EncodeWriteMsg(
	pubKeyIdRcv ed25519.PublicKey,
	pukKeyIdSnd ed25519.PublicKey,
	sharedSecret []byte,
	data []byte,
	wr io.Writer) (n int, err error) {

	var buffer bytes.Buffer
	w := &buffer

	// Construct the header with version and message type for MSG
	const versionValue uint8 = 0 // Assuming version 1 for this example
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
	nonce, err := generateRandom24()
	if err != nil {
		return 0, err
	}
	if _, err := w.Write(nonce[:]); err != nil {
		return 0, err
	}

	slog.Debug("shareds4", slog.Any("sharedSecret", sharedSecret))
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

func Decode(b []byte, n int, privKeyId ed25519.PrivateKey, privKeyEp *ecdh.PrivateKey, pubKeyIdRcv ed25519.PublicKey, sharedSecret []byte) (*Message, error) {
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

	var pubKeyIdRcvShort [4]byte
	if _, err := io.ReadFull(buf, pubKeyIdRcvShort[:]); err != nil {
		return nil, err
	}
	mh.PubKeyIdRcvShort = pubKeyIdRcvShort

	switch messageType {
	case uint8(Init):
		if n < MinMsgInitSize {
			return nil, errors.New("size is below minimum")
		}

		var pukKeyIdSnd [32]byte
		if _, err := io.ReadFull(buf, pukKeyIdSnd[:]); err != nil {
			return nil, err
		}
		mh.PukKeyIdSnd = pukKeyIdSnd[:]
		copy(mh.PukKeyIdSndShort[:], pukKeyIdSnd[:4])
		return DecodeInit(buf, n, privKeyId, mh)
	case uint8(InitReply):
		if n < MinMsgInitReplySize {
			return nil, errors.New("size is below minimum")
		}
		var pukKeyIdSnd [4]byte
		if _, err := io.ReadFull(buf, pukKeyIdSnd[:]); err != nil {
			return nil, err
		}

		return DecodeInitReply(buf, n, privKeyEp, pubKeyIdRcv, mh)
	case uint8(Msg):
		if n < MinMsgSize {
			return nil, errors.New("size is below minimum")
		}
		var pukKeyIdSnd [4]byte
		if _, err := io.ReadFull(buf, pukKeyIdSnd[:]); err != nil {
			return nil, err
		}
		mh.PukKeyIdSndShort = pukKeyIdSnd

		return DecodeMsg(buf, n, sharedSecret, mh)
	default:
		// Handle any unexpected message types if necessary.
		return nil, errors.New("unsupported message type")
	}
}

// DecodeInit decodes the message from a byte slice
func DecodeInit(buf *bytes.Buffer, n int, privKeyIdRcv ed25519.PrivateKey, mh MessageHeader) (*Message, error) {
	// Read the ephemeral public key
	b := make([]byte, 32)
	if _, err := io.ReadFull(buf, b); err != nil {
		return nil, err
	}
	pubKeyEpSnd, err := ecdh.X25519().NewPublicKey(b)
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
	secret, err := privKeyIdRcvCurve.ECDH(pubKeyEpSnd)
	if err != nil {
		return nil, err
	}

	// Initialize AEAD
	aead, err := chacha20poly1305.NewX(secret)
	if err != nil {
		return nil, err
	}
	// Read the rest of the data for decryption
	encryptedData := make([]byte, n-93)
	if _, err := io.ReadFull(buf, encryptedData); err != nil {
		return nil, err
	}

	// Decrypt the data
	buf.Reset()
	decryptedData, err := aead.Open(nil, nonce[:], encryptedData, buf.Bytes()[0:93])
	if err != nil {
		return nil, err
	}

	fillBufferLength := uint16(decryptedData[0])<<8 + uint16(decryptedData[1])

	// Construct the InitMessage
	m := &Message{
		MessageHeader: mh,
		PukKeyEpSnd:   pubKeyEpSnd,
		PayloadRaw:    decryptedData[fillBufferLength:],
		SharedSecret:  secret,
	}
	return m, nil
}

// DecodeInitReply decodes an INIT_REPLY packet.
func DecodeInitReply(buf *bytes.Buffer, n int, privKeyEp *ecdh.PrivateKey, pubKeyIdRcv ed25519.PublicKey, mh MessageHeader) (*Message, error) {
	var pubKeyEpSndBytes [32]byte
	if _, err := io.ReadFull(buf, pubKeyEpSndBytes[:]); err != nil {
		return nil, err
	}

	pubKeyIdRcvCurve, _ := ed25519PublicKeyToCurve25519(pubKeyIdRcv)
	oldSecret, _ := privKeyEp.ECDH(pubKeyIdRcvCurve)

	// Read nonce
	var nonce [24]byte
	if _, err := io.ReadFull(buf, nonce[:]); err != nil {
		return nil, err
	}

	// Decrypt the data
	aead, err := chacha20poly1305.NewX(oldSecret)
	if err != nil {
		return nil, err
	}
	encryptedData := make([]byte, buf.Len()) // Exclude auth tag size from the total length
	if _, err := io.ReadFull(buf, encryptedData); err != nil {
		return nil, err
	}

	buf.Reset()
	decryptedData, err := aead.Open(nil, nonce[:], encryptedData, buf.Bytes()[0:65])
	if err != nil {
		return nil, err
	}

	pubKeyEpSnd, err := ecdh.X25519().NewPublicKey(pubKeyEpSndBytes[:])
	if err != nil {
		return nil, err
	}
	newSecret, err := privKeyEp.ECDH(pubKeyEpSnd)
	if err != nil {
		return nil, err
	}
	// Construct the InitReplyMessage
	m := &Message{
		MessageHeader: mh,
		PukKeyEpSnd:   pubKeyEpSnd,
		PayloadRaw:    decryptedData,
		SharedSecret:  newSecret,
	}

	return m, nil
}

// DecodeMsg decodes a MSG packet.
func DecodeMsg(buf *bytes.Buffer, n int, sharedSecret []byte, mh MessageHeader) (*Message, error) {
	// Read nonce
	var nonce [24]byte
	if _, err := io.ReadFull(buf, nonce[:]); err != nil {
		return nil, err
	}

	slog.Debug("shareds3", slog.Any("secret", sharedSecret))

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
		PayloadRaw:    decryptedData,
	}

	return m, nil
}

func DecodeConnId(b []byte) ([8]byte, error) {
	buf := bytes.NewBuffer(b)

	// Read the header byte
	_, err := buf.ReadByte()
	if err != nil {
		return [8]byte{}, err
	}

	var ret [8]byte
	buf.Read(ret[:])

	return ret, nil
}

func generateRandom24() ([24]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, err
	}
	return nonce, nil
}

func generateRandom32() ([32]byte, error) {
	var nonce [32]byte
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
