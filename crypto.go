package tomtp

import (
	"crypto/ecdh"
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
	Msg

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
	pubKeyIdSnd *ecdh.PublicKey,
	privKeyEpSnd *ecdh.PrivateKey,
	sn uint64,
	data []byte,
	wr io.Writer) (n int, err error) {

	// Write the public key
	headerAndCryptoBuffer := make([]byte, 0, 9+64)

	// Write header
	header := (Version << 2) | uint8(Init)
	headerAndCryptoBuffer = append(headerAndCryptoBuffer, header)

	// Write connection ID
	connId := binary.LittleEndian.Uint64(pubKeyIdRcv.Bytes()) ^ binary.LittleEndian.Uint64(pubKeyIdSnd.Bytes())
	headerAndCryptoBuffer = binary.LittleEndian.AppendUint64(headerAndCryptoBuffer, connId)

	// Write public keys
	headerAndCryptoBuffer = append(headerAndCryptoBuffer, pubKeyIdSnd.Bytes()...)
	headerAndCryptoBuffer = append(headerAndCryptoBuffer, privKeyEpSnd.PublicKey().Bytes()...)

	// Perform ECDH
	noPerfectForwardSecret, err := privKeyEpSnd.ECDH(pubKeyIdRcv)
	if err != nil {
		return 0, err
	}

	// Prepare data with fill bytes
	maxLenFill := max(0, startMtu-MinMsgInitSize-2-len(data))
	fillBytes := make([]byte, maxLenFill+2)
	binary.LittleEndian.PutUint16(fillBytes, uint16(maxLenFill))
	data = append(fillBytes, data...)

	// Encrypt and write data
	return chainedEncrypt(sn, noPerfectForwardSecret, headerAndCryptoBuffer, data, wr)
}

func EncodeWriteInitReply(
	pubKeyIdRcv *ecdh.PublicKey,
	privKeyIdSnd *ecdh.PrivateKey,
	privKeyEpSnd *ecdh.PrivateKey,
	sharedSecret []byte,
	sn uint64,
	data []byte,
	wr io.Writer) (n int, err error) {

	// Preallocate buffer with capacity for header and crypto data
	headerAndCryptoBuffer := make([]byte, 0, 9+32)

	// Write header
	header := (Version << 2) | uint8(InitReply)
	headerAndCryptoBuffer = append(headerAndCryptoBuffer, header)

	// Write connection ID
	pubKeyIdSnd := privKeyIdSnd.Public().(*ecdh.PublicKey)
	connId := binary.LittleEndian.Uint64(pubKeyIdRcv.Bytes()) ^ binary.LittleEndian.Uint64(pubKeyIdSnd.Bytes())
	headerAndCryptoBuffer = binary.LittleEndian.AppendUint64(headerAndCryptoBuffer, connId)

	// Write ephemeral public key
	headerAndCryptoBuffer = append(headerAndCryptoBuffer, privKeyEpSnd.PublicKey().Bytes()...)

	// Encrypt and write data
	return chainedEncrypt(sn, sharedSecret, headerAndCryptoBuffer, data, wr)
}

// EncodeWriteMsg encodes and writes a MSG packet.
func EncodeWriteMsg(
	snd bool,
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyIdSnd *ecdh.PublicKey,
	sharedSecret []byte,
	sn uint64,
	data []byte,
	wr io.Writer) (n int, err error) {

	// Preallocate buffer with capacity for header and connection ID
	headerBuffer := make([]byte, 0, 9)

	// Write header
	header := (Version << 2) | uint8(Msg)
	headerBuffer = append(headerBuffer, header)

	// Write connection ID
	connId := binary.LittleEndian.Uint64(pubKeyIdRcv.Bytes()) ^ binary.LittleEndian.Uint64(pubKeyIdSnd.Bytes())
	headerBuffer = binary.LittleEndian.AppendUint64(headerBuffer, connId)

	// Encrypt and write data
	return chainedEncrypt(sn, sharedSecret, headerBuffer, data, wr)
}

func DecodeHeader(
	b []byte,
	privKeyId *ecdh.PrivateKey,
	privKeyEp *ecdh.PrivateKey,
	pubKeyIdRcv *ecdh.PublicKey,
	sharedSecret []byte) (*Message, error) {

	// Read the header byte and connId
	header, connId, err := decodeConnId(b)
	if err != nil {
		return nil, err
	}

	return Decode(b, header, connId, privKeyId, privKeyEp, pubKeyIdRcv, sharedSecret)
}

func decodeConnId(b []byte) (header byte, connId uint64, err error) {
	// Read the header byte and connId
	if len(b) < 9 {
		return 0, 0, errors.New("header needs to be at least 9 bytes")
	}

	header = b[0]
	connId = binary.LittleEndian.Uint64(b[1:9])

	return header, connId, nil
}

func Decode(b []byte, header byte, connId uint64, privKeyId *ecdh.PrivateKey, privKeyEp *ecdh.PrivateKey, pubKeyIdRcv *ecdh.PublicKey, sharedSecret []byte) (*Message, error) {
	if len(b) < MsgSize {
		return nil, errors.New("size is below message header size")
	}

	versionValue := (header >> 2) & 0x3f
	messageType := header & 0x03

	if versionValue != Version {
		return nil, errors.New("invalid version")
	}

	mh := MessageHeader{
		Type:   MsgType(messageType),
		ConnId: connId,
	}

	switch messageType {
	case uint8(Init):
		if len(b) < MinMsgInitSize+8 { //8 is minimum payload, otherwise sn cannot be encrypted
			return nil, errors.New("size is below minimum init")
		}
		return DecodeInit(b, privKeyId, privKeyEp, mh)
	case uint8(InitReply):
		if len(b) < MinMsgInitReplySize+8 { //8 is minimum payload, otherwise sn cannot be encrypted
			return nil, errors.New("size is below minimum init reply")
		}
		return DecodeInitReply(b, privKeyEp, mh)
	case uint8(Msg):
		if len(b) < MinMsgSize+8 { //8 is minimum payload, otherwise sn cannot be encrypted
			return nil, errors.New("size is below minimum")
		}
		return DecodeMsg(b, sharedSecret, mh)
	default:
		// Handle any unexpected message types if necessary.
		return nil, errors.New("unsupported message type")
	}
}

// DecodeInit decodes the message from a byte slice
func DecodeInit(
	raw []byte,
	privKeyIdRcv *ecdh.PrivateKey,
	privKeyEpRcv *ecdh.PrivateKey,
	mh MessageHeader) (*Message, error) {

	pukKeyIdSnd, err := ecdh.X25519().NewPublicKey(raw[9 : 9+32])
	if err != nil {
		return nil, err
	}
	mh.PukKeyIdSnd = pukKeyIdSnd

	pubKeyEpSnd, err := ecdh.X25519().NewPublicKey(raw[9+32 : 9+64])
	if err != nil {
		return nil, err
	}
	mh.PukKeyEpSnd = pubKeyEpSnd

	noPerfectForwardSecret, err := privKeyIdRcv.ECDH(pubKeyEpSnd)
	if err != nil {
		return nil, err
	}

	sn, decryptedData, err := chainedDecrypt(
		noPerfectForwardSecret,
		raw[0:MinMsgInitSize-MacSize-SnSize],
		raw[MinMsgInitSize-MacSize-SnSize:],
	)
	if err != nil {
		return nil, err
	}

	fillBufferLength := binary.LittleEndian.Uint16(decryptedData[:2])

	secret, err := privKeyEpRcv.ECDH(pubKeyEpSnd)
	if err != nil {
		return nil, err
	}

	return &Message{
		MessageHeader: mh,
		PayloadRaw:    decryptedData[2+fillBufferLength:],
		SharedSecret:  secret,
		Sn:            sn,
	}, nil
}

// DecodeInitReply decodes an INIT_REPLY packet.
func DecodeInitReply(raw []byte, privKeyEpSnd *ecdh.PrivateKey, mh MessageHeader) (*Message, error) {
	pubKeyEpRcv, err := ecdh.X25519().NewPublicKey(raw[9 : 9+32])
	if err != nil {
		return nil, err
	}

	secret, err := privKeyEpSnd.ECDH(pubKeyEpRcv)
	if err != nil {
		return nil, err
	}

	sn, decryptedData, err := chainedDecrypt(
		secret,
		raw[0:MinMsgInitReplySize-MacSize-SnSize],
		raw[MinMsgInitReplySize-MacSize-SnSize:],
	)
	if err != nil {
		return nil, err
	}

	return &Message{
		MessageHeader: mh,
		PayloadRaw:    decryptedData,
		SharedSecret:  secret,
		Sn:            sn,
	}, nil
}

// DecodeMsg decodes a MSG packet.
func DecodeMsg(raw []byte, secret []byte, mh MessageHeader) (*Message, error) {
	sn, decryptedData, err := chainedDecrypt(
		secret,
		raw[0:MinMsgSize-MacSize-SnSize],
		raw[MinMsgSize-MacSize-SnSize:],
	)
	if err != nil {
		return nil, err
	}

	return &Message{
		MessageHeader: mh,
		PayloadRaw:    decryptedData,
		Sn:            sn,
	}, nil
}

func chainedEncrypt(sn uint64, sharedSecret []byte, headerAndCrypto []byte, data []byte, wr io.Writer) (int, error) {
	if len(data) < 8 {
		return 0, errors.New("data too short")
	}

	snSer := make([]byte, 8)
	binary.LittleEndian.PutUint64(snSer, sn)

	nonceDet := make([]byte, 12)
	for i := 0; i < 12; i++ {
		nonceDet[i] = sharedSecret[i] ^ snSer[i%8]
	}

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return 0, err
	}

	aead2, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		return 0, err
	}

	encData := aead.Seal(nil, nonceDet, data, headerAndCrypto)
	nonceRand := encData[0:24]

	encData2 := aead2.Seal(nil, nonceRand, snSer, nil)

	// Prepare the full encrypted message
	fullMessage := make([]byte, 0, len(headerAndCrypto)+8+len(encData))
	fullMessage = append(fullMessage, headerAndCrypto...)
	fullMessage = append(fullMessage, encData2[:8]...)
	fullMessage = append(fullMessage, encData...)

	// Write the full message in one operation
	return wr.Write(fullMessage)
}

func chainedDecrypt(sharedSecret []byte, header []byte, encData []byte) (sn uint64, decoded []byte, err error) {
	if len(encData) < 32 { // 8 bytes for encSn + 24 bytes for nonceRand
		return 0, nil, errors.New("encrypted data too short")
	}

	encSn := encData[0:8]
	ciphertext := encData[8:]
	nonceRand := ciphertext[:24]

	snSer := openNoVerify(sharedSecret, nonceRand, encSn)

	nonceDet := make([]byte, 12)
	for i := 0; i < 12; i++ {
		nonceDet[i] = sharedSecret[i] ^ snSer[i%8]
	}

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return 0, nil, err
	}

	data, err := aead.Open(nil, nonceDet, ciphertext, header)
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
