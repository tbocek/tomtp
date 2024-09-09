package tomtp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
)

type MsgType uint8

const (
	Init MsgType = iota
	InitReply
	MsgSnd
	MsgRcv

	MessageHeaderSize = 33
	MacSize           = 16
	// MinMsgInitSize      [version 6bit | type 2bit | pubKeyIdShortRcv 64bit | pukKeyIdSnd 256bit] pukKeyEpSnd 256bit | nonce 192bit | [fill len 16bit | fill encrypted | payload encrypted] | mac 128bit
	MinMsgInitSize = 97 + MacSize
	// MinMsgInitReplySize [version 6bit | type 2bit | pubKeyIdShortRcv 64bit XOR pukKeyIdShortSnd 64bit] pukKeyEpSnd 256bit | nonce 192bit | [payload encrypted] | mac 128bit
	MinMsgInitReplySize = 65 + MacSize
	// MinMsgSize          [version 6bit | type 2bit | pubKeyIdShortRcv 64bit XOR pukKeyIdShortSnd 64bit] nonce 192bit | [payload encrypted] | mac 128bit
	MinMsgSize = MessageHeaderSize + MacSize
	StartNonce = 9

	Version uint8 = 0 // Assuming version 1 for this example
)

type MessageHeader struct {
	Type        MsgType
	ConnId      uint64
	PukKeyIdSnd *ecdh.PublicKey
	PukKeyEpSnd *ecdh.PublicKey
}

type Message struct {
	MessageHeader
	PayloadRaw   []byte
	Payload      *Payload
	Fill         []byte
	SharedSecret []byte
}

func EncodeWriteInit(
	pubKeyIdRcv *ecdh.PublicKey,
	pukKeyIdSnd *ecdh.PublicKey,
	privKeyEpSnd *ecdh.PrivateKey,
	data []byte,
	wr io.Writer) (n int, err error) {

	// Write the public key
	var buffer bytes.Buffer
	w := &buffer

	//magic, version, and type
	header := (Version << 2) | uint8(Init)
	if err := w.WriteByte(header); err != nil {
		return 0, err
	}

	// 64bit connection Id
	connId := encodeXor(pubKeyIdRcv.Bytes(), pukKeyIdSnd.Bytes())
	if err := binary.Write(w, binary.LittleEndian, connId); err != nil {
		return 0, err
	}

	//nonce
	nonce, err := generateRandom24()
	if err != nil {
		return 0, err
	}
	// create and write nonce (192bit = 24byte Nonce)
	if _, err := w.Write(nonce[:]); err != nil {
		return 0, err
	}

	// id public key
	if _, err := w.Write(pukKeyIdSnd.Bytes()); err != nil {
		return 0, err
	}

	// ephemeral public key
	if _, err := w.Write(privKeyEpSnd.PublicKey().Bytes()); err != nil {
		return 0, err
	}

	//encrypted data + mac
	secret, err := privKeyEpSnd.ECDH(pubKeyIdRcv)
	if err != nil {
		return 0, err
	}
	sharedSecret := secret[:]

	aead, err := chacha20poly1305.NewX(sharedSecret[:])
	if err != nil {
		return 0, err
	}

	//prevent amplification attacks
	maxLenFill := startMtu - MinMsgInitSize - 2 - len(data)
	if maxLenFill < 0 {
		maxLenFill = 0
	}
	fillBytes := make([]byte, maxLenFill+2)
	fillBytes[0] = byte(maxLenFill >> 8)
	fillBytes[1] = byte(maxLenFill & 0xFF)
	data = append(fillBytes, data...)
	additionalData := buffer.Bytes()

	n, err = wr.Write(additionalData)
	if err != nil {
		return 0, err
	}

	encData := aead.Seal(nil, nonce[:], data, additionalData)
	nn, err := wr.Write(encData)
	n += nn

	return n, err
}

func EncodeWriteInitReply(
	pubKeyIdRcv *ecdh.PublicKey,
	privKeyIdSnd *ecdh.PrivateKey,
	pubKeyEpRcv *ecdh.PublicKey,
	privKeyEpSnd *ecdh.PrivateKey,
	sharedSecret []byte,
	data []byte,
	wr io.Writer) (n int, err error) {

	var buffer bytes.Buffer
	w := &buffer

	//magic, version, and type
	header := (Version << 2) | uint8(InitReply)
	if err := w.WriteByte(header); err != nil {
		return 0, err
	}

	// 64bit connection Id
	connId := encodeXor(pubKeyIdRcv.Bytes(), privKeyIdSnd.Public().(*ecdh.PublicKey).Bytes())
	if err := binary.Write(w, binary.LittleEndian, connId); err != nil {
		return 0, err
	}

	// nonce
	nonce, err := generateRandom24()
	if err != nil {
		return 0, err
	}
	if _, err := w.Write(nonce[:]); err != nil {
		return 0, err
	}

	// ephemeral public key
	if _, err := w.Write(privKeyEpSnd.PublicKey().Bytes()); err != nil {
		return 0, err
	}

	// Encrypt the payload
	aead, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		return 0, err
	}
	encData := aead.Seal(nil, nonce[:], data, buffer.Bytes())
	if _, err := w.Write(encData); err != nil {
		return 0, err
	}

	n, err = wr.Write(buffer.Bytes())
	return n, err
}

// EncodeWriteMsg encodes and writes a MSG packet.
func EncodeWriteMsg(
	snd bool,
	pubKeyIdRcv *ecdh.PublicKey,
	pukKeyIdSnd *ecdh.PublicKey,
	sharedSecret []byte,
	data []byte,
	wr io.Writer) (n int, err error) {

	var buffer bytes.Buffer
	w := &buffer

	//magic, version, and type
	var header = Version << 2
	if snd {
		header |= uint8(MsgSnd)
	} else {
		header |= uint8(MsgRcv)
	}
	if err := w.WriteByte(header); err != nil {
		return 0, err
	}

	// 64bit connection Id
	connId := encodeXor(pubKeyIdRcv.Bytes(), pukKeyIdSnd.Bytes())
	if err := binary.Write(w, binary.LittleEndian, connId); err != nil {
		return 0, err
	}

	// nonce
	nonce, err := generateRandom24()
	if err != nil {
		return 0, err
	}
	if _, err := w.Write(nonce[:]); err != nil {
		return 0, err
	}

	// data + mac
	aead, err := chacha20poly1305.NewX(sharedSecret[:])
	if err != nil {
		return 0, err
	}
	encData := aead.Seal(nil, nonce[:], data, buffer.Bytes())
	if _, err := w.Write(encData); err != nil {
		return 0, err
	}

	n, err = wr.Write(buffer.Bytes())
	return n, err
}

func DecodeHeader(
	b []byte,
	offset int,
	bufLen int,
	privKeyId *ecdh.PrivateKey,
	privKeyEp *ecdh.PrivateKey,
	pubKeyIdRcv *ecdh.PublicKey,
	sharedSecret []byte) (*Message, error) {
	// Read the header byte and connId
	header, connId, n, err := DecodeConnId(b)
	if err != nil {
		return nil, err
	}
	return Decode(b, offset+n, bufLen, header, connId, privKeyId, privKeyEp, pubKeyIdRcv, sharedSecret)
}

func DecodeConnId(b []byte) (header byte, connId uint64, n int, err error) {
	buf := bytes.NewBuffer(b)

	// Read the header byte
	header, err = buf.ReadByte()
	if err != nil {
		return 0, 0, 0, err
	}

	if err := binary.Read(buf, binary.LittleEndian, &connId); err != nil {
		return 0, 0, 0, err
	}

	return header, connId, 9, nil
}

func Decode(b []byte, offset int, bufLen int, header byte, connId uint64, privKeyId *ecdh.PrivateKey, privKeyEp *ecdh.PrivateKey, pubKeyIdRcv *ecdh.PublicKey, sharedSecret []byte) (*Message, error) {
	if bufLen < MessageHeaderSize {
		return nil, errors.New("size is below message header size")
	}
	var mh MessageHeader
	buf := bytes.NewBuffer(b[offset:])

	//magic, version, and type
	versionValue := (header >> 2) & 0x3f
	messageType := header & 0x03
	if versionValue != Version {
		return nil, errors.New("invalid version")
	}
	mh.Type = MsgType(messageType)

	// 64bit connection Id
	mh.ConnId = connId

	// Skip nonce, as we use the slice directly
	buf.Next(24)

	switch messageType {
	case uint8(Init):
		if bufLen < MinMsgInitSize {
			return nil, errors.New("size is below minimum init")
		}
		return DecodeInit(b, buf, privKeyId, privKeyEp, mh)
	case uint8(InitReply):
		if bufLen < MinMsgInitReplySize {
			return nil, errors.New("size is below minimum init reply")
		}
		return DecodeInitReply(b, buf, privKeyEp, mh)
	case uint8(MsgRcv), uint8(MsgSnd):
		if bufLen < MinMsgSize {
			return nil, errors.New("size is below minimum")
		}
		return DecodeMsg(b, buf, sharedSecret, mh)
	default:
		// Handle any unexpected message types if necessary.
		return nil, errors.New("unsupported message type")
	}
}

// DecodeInit decodes the message from a byte slice
func DecodeInit(
	raw []byte,
	buf *bytes.Buffer,
	privKeyIdRcv *ecdh.PrivateKey,
	privKeyEpRcv *ecdh.PrivateKey,
	mh MessageHeader) (*Message, error) {
	// Read the public key
	var pukKeyIdSnd [32]byte
	if _, err := io.ReadFull(buf, pukKeyIdSnd[:]); err != nil {
		return nil, err
	}

	pub, err := ecdh.X25519().NewPublicKey(pukKeyIdSnd[:])
	if err != nil {
		return nil, err
	}
	mh.PukKeyIdSnd = pub

	// Read the ephemeral public key
	b := make([]byte, 32)
	if _, err := io.ReadFull(buf, b); err != nil {
		return nil, err
	}
	pubKeyEpSnd, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return nil, err
	}
	mh.PukKeyEpSnd = pubKeyEpSnd

	// Calculate the shared secret
	noPerfectForwardSecret, err := privKeyIdRcv.ECDH(pubKeyEpSnd)
	if err != nil {
		return nil, err
	}

	// Initialize AEAD
	aead, err := chacha20poly1305.NewX(noPerfectForwardSecret)
	if err != nil {
		return nil, err
	}

	// Decrypt the data
	decryptedData, err := aead.Open(nil,
		raw[StartNonce:MessageHeaderSize],
		raw[MinMsgInitSize-MacSize:],
		raw[0:MinMsgInitSize-MacSize])
	if err != nil {
		return nil, err
	}

	fillBufferLength := uint16(decryptedData[0])<<8 + uint16(decryptedData[1])

	//since we will use an ephemeral key anyway, we do it now, and store the shared secret
	secret, err := privKeyEpRcv.ECDH(pubKeyEpSnd)
	if err != nil {
		return nil, err
	}

	// Construct the InitMessage
	m := &Message{
		MessageHeader: mh,
		PayloadRaw:    decryptedData[2+fillBufferLength:],
		SharedSecret:  secret,
	}
	return m, nil
}

// DecodeInitReply decodes an INIT_REPLY packet.
func DecodeInitReply(raw []byte, buf *bytes.Buffer, privKeyEpSnd *ecdh.PrivateKey, mh MessageHeader) (*Message, error) {
	var pubKeyEpRcvBytes [32]byte
	if _, err := io.ReadFull(buf, pubKeyEpRcvBytes[:]); err != nil {
		return nil, err
	}
	pubKeyEpRcv, err := ecdh.X25519().NewPublicKey(pubKeyEpRcvBytes[:])

	secret, err := privKeyEpSnd.ECDH(pubKeyEpRcv)
	if err != nil {
		return nil, err
	}

	// Decrypt the data
	aead, err := chacha20poly1305.NewX(secret)
	if err != nil {
		return nil, err
	}

	// Decrypt the data
	decryptedData, err := aead.Open(nil,
		raw[StartNonce:MessageHeaderSize],
		raw[MinMsgInitReplySize-MacSize:],
		raw[0:MinMsgInitReplySize-MacSize])
	if err != nil {
		return nil, err
	}

	// Construct the InitReplyMessage
	m := &Message{
		MessageHeader: mh,
		PayloadRaw:    decryptedData,
		SharedSecret:  secret,
	}

	return m, nil
}

// DecodeMsg decodes a MSG packet.
func DecodeMsg(raw []byte, buf *bytes.Buffer, secret []byte, mh MessageHeader) (*Message, error) {
	// Decrypt the data
	aead, err := chacha20poly1305.NewX(secret)
	if err != nil {
		return nil, err
	}

	// Decrypt the data
	decryptedData, err := aead.Open(nil,
		raw[StartNonce:MessageHeaderSize],
		raw[MinMsgSize-MacSize:],
		raw[0:MinMsgSize-MacSize])
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

func generateRandom24() ([24]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, err
	}
	return nonce, nil
}

func encodeXor(data1 []byte, data2 []byte) uint64 {
	return binary.LittleEndian.Uint64(data1) ^ binary.LittleEndian.Uint64(data2)
}
