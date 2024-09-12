package tomtp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
)

type MsgType uint8

const (
	Init MsgType = iota
	InitReply
	MsgSnd
	MsgRcv

	MsgSize = 17
	MacSize = 16
	SnSize  = 8
	// MinMsgInitSize      [version 6bit | type 2bit | pubKeyIdShortRcv 64bit | pukKeyIdSnd 256bit] pukKeyEpSnd 256bit | nonce 192bit | [fill len 16bit | fill encrypted | payload encrypted] | mac 128bit
	MinMsgInitSize = 81 + MacSize
	// MinMsgInitReplySize [version 6bit | type 2bit | pubKeyIdShortRcv 64bit XOR pukKeyIdShortSnd 64bit] pukKeyEpSnd 256bit | nonce 192bit | [payload encrypted] | mac 128bit
	MinMsgInitReplySize = 49 + MacSize
	// MinMsgSize          [version 6bit | type 2bit | pubKeyIdShortRcv 64bit XOR pukKeyIdShortSnd 64bit] nonce 192bit | [payload encrypted] | mac 128bit
	MinMsgSize = MsgSize + MacSize

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
	Sn           uint64
}

func EncodeWriteInit(
	pubKeyIdRcv *ecdh.PublicKey,
	pukKeyIdSnd *ecdh.PublicKey,
	privKeyEpSnd *ecdh.PrivateKey,
	sn uint64,
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

	// id public key
	if _, err := w.Write(pukKeyIdSnd.Bytes()); err != nil {
		return 0, err
	}

	// ephemeral public key
	if _, err := w.Write(privKeyEpSnd.PublicKey().Bytes()); err != nil {
		return 0, err
	}

	//encrypted data + mac
	noPerfectForwardSecret, err := privKeyEpSnd.ECDH(pubKeyIdRcv)
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

	nn, err := chainedEncrypt(sn, noPerfectForwardSecret, data, additionalData, wr)
	if err != nil {
		return 0, err
	}
	n += nn
	return n, err
}

func EncodeWriteInitReply(
	pubKeyIdRcv *ecdh.PublicKey,
	privKeyIdSnd *ecdh.PrivateKey,
	pubKeyEpRcv *ecdh.PublicKey,
	privKeyEpSnd *ecdh.PrivateKey,
	sharedSecret []byte,
	sn uint64,
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

	// ephemeral public key
	if _, err := w.Write(privKeyEpSnd.PublicKey().Bytes()); err != nil {
		return 0, err
	}

	nn, err := chainedEncrypt(sn, sharedSecret, data, buffer.Bytes(), wr)
	if err != nil {
		return 0, err
	}
	n += nn
	return n, err
}

// EncodeWriteMsg encodes and writes a MSG packet.
func EncodeWriteMsg(
	snd bool,
	pubKeyIdRcv *ecdh.PublicKey,
	pukKeyIdSnd *ecdh.PublicKey,
	sharedSecret []byte,
	sn uint64,
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

	nn, err := chainedEncrypt(sn, sharedSecret, data, buffer.Bytes(), wr)
	if err != nil {
		return 0, err
	}
	n += nn
	return n, err
}

func DecodeHeader(
	b []byte,
	privKeyId *ecdh.PrivateKey,
	privKeyEp *ecdh.PrivateKey,
	pubKeyIdRcv *ecdh.PublicKey,
	sharedSecret []byte) (*Message, error) {
	// Read the header byte and connId
	header, connId, _, err := DecodeConnId(b)
	if err != nil {
		return nil, err
	}
	return Decode(b, header, connId, privKeyId, privKeyEp, pubKeyIdRcv, sharedSecret)
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

func Decode(b []byte, header byte, connId uint64, privKeyId *ecdh.PrivateKey, privKeyEp *ecdh.PrivateKey, pubKeyIdRcv *ecdh.PublicKey, sharedSecret []byte) (*Message, error) {
	if len(b) < MsgSize {
		return nil, errors.New("size is below message header size")
	}
	var mh MessageHeader
	buf := bytes.NewBuffer(b)

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
	buf.Next(9)

	switch messageType {
	case uint8(Init):
		if len(b) < MinMsgInitSize {
			return nil, errors.New("size is below minimum init")
		}
		return DecodeInit(b, buf, privKeyId, privKeyEp, mh)
	case uint8(InitReply):
		if len(b) < MinMsgInitReplySize {
			return nil, errors.New("size is below minimum init reply")
		}
		return DecodeInitReply(b, buf, privKeyEp, mh)
	case uint8(MsgRcv), uint8(MsgSnd):
		if len(b) < MinMsgSize {
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

	// Decrypt the data
	sn, decryptedData, err := chainedDecrypt(
		noPerfectForwardSecret,
		raw[MinMsgInitSize-MacSize-SnSize:],
		raw[0:MinMsgInitSize-MacSize-SnSize])
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
		Sn:            sn,
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
	sn, decryptedData, err := chainedDecrypt(
		secret,
		raw[MinMsgInitReplySize-MacSize-SnSize:],
		raw[0:MinMsgInitReplySize-MacSize-SnSize])
	if err != nil {
		return nil, err
	}

	// Construct the InitReplyMessage
	m := &Message{
		MessageHeader: mh,
		PayloadRaw:    decryptedData,
		SharedSecret:  secret,
		Sn:            sn,
	}

	return m, nil
}

// DecodeMsg decodes a MSG packet.
func DecodeMsg(raw []byte, buf *bytes.Buffer, secret []byte, mh MessageHeader) (*Message, error) {
	// Decrypt the data
	sn, decryptedData, err := chainedDecrypt(
		secret,
		raw[MinMsgSize-MacSize-SnSize:],
		raw[0:MinMsgSize-MacSize-SnSize])
	if err != nil {
		return nil, err
	}

	// Construct and return the message
	m := &Message{
		MessageHeader: mh,
		PayloadRaw:    decryptedData,
		Sn:            sn,
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

func chainedEncrypt(sn uint64, sharedSecret []byte, data []byte, additionalData []byte, wr io.Writer) (int, error) {
	snSer := make([]byte, 8)
	binary.LittleEndian.PutUint64(snSer, sn)
	nonceDet := make([]byte, 12)

	for i := 0; i < 12; i++ {
		nonceDet[i] = sharedSecret[i] ^ snSer[i%8]
	}

	aead, err := chacha20poly1305.New(sharedSecret[:])
	if err != nil {
		return 0, err
	}

	aead2, err := chacha20poly1305.NewX(sharedSecret[:])
	if err != nil {
		return 0, err
	}

	encData := aead.Seal(nil, nonceDet[:], data, additionalData)

	nonceRand := make([]byte, 24)
	for i := 0; i < 24; i++ {
		//encData has an entropy of 16bytes random (128bit) when paket is empty, add other data
		//to increase the chances of uniqueness. Not sure if necessary
		nonceRand[i] = additionalData[i%len(additionalData)] ^ encData[i%len(encData)]
	}

	encData2 := aead2.Seal(nil, nonceRand, snSer, nil)

	n, err := wr.Write(additionalData)
	if err != nil {
		return 0, err
	}

	n, err = wr.Write(encData)
	if err != nil {
		return 0, err
	}

	nn, err := wr.Write(encData2[0:8])
	if err != nil {
		return 0, err
	}
	n += nn
	return n, err
}

func chainedDecrypt(sharedSecret []byte, encData []byte, additionalData []byte) (sn uint64, decoded []byte, err error) {
	encSn := encData[len(encData)-8:]
	ciphertext := encData[:len(encData)-8]

	nonceRand := make([]byte, 24)
	for i := 0; i < 24; i++ {
		//encData has an entropy of 16bytes random (128bit) when paket is empty, add other data
		//to increase the chances of uniqueness. Not sure if necessary
		nonceRand[i] = additionalData[i%len(additionalData)] ^ ciphertext[i%len(ciphertext)]
	}

	snSer := openNoVerify(sharedSecret, nonceRand, encSn)

	// Calculate nonceDet
	nonceDet := make([]byte, 12)
	for i := 0; i < 12; i++ {
		nonceDet[i] = sharedSecret[i] ^ snSer[i%8]
	}

	aead, err := chacha20poly1305.New(sharedSecret[:])
	if err != nil {
		return 0, nil, err
	}

	// Decrypt the main data
	data, err := aead.Open(nil, nonceDet[:], ciphertext, additionalData)
	if err != nil {
		return 0, nil, err
	}

	sn = binary.LittleEndian.Uint64(snSer)
	return sn, data, nil
}

// inspired by: https://github.com/golang/crypto/blob/master/chacha20poly1305/chacha20poly1305_generic.go
func openNoVerify(sharedSecret []byte, nonce []byte, encoded []byte) (snSer []byte) {
	s, _ := chacha20.NewUnauthenticatedCipher(sharedSecret, nonce)
	s.SetCounter(1) // Set the counter to 1, skipping 32 bytes

	// Decrypt the ciphertext
	snSer = make([]byte, 8)
	s.XORKeyStream(snSer, encoded)

	return snSer
}
