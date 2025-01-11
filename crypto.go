package tomtp

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

type MsgType uint8

const (
	VersionMagic uint8 = 77

	InitSndMsgType MsgType = iota
	InitRcvMsgType
	DataMsgType
)

const (
	MacSize = 16
	SnSize  = 6 // Sequence number size is 48bit / 6 bytes
	//MinPayloadSize is the minimum payload size in bytes. We need at least 8 bytes as
	// 8 + the MAC size (16 bytes) is 24 bytes, which is used as the input for
	// sealing with chacha20poly1305.NewX().
	MinPayloadSize = 8
	PubKeySize     = 32

	HeaderSize    = 1
	ConnIdSize    = 8
	MsgHeaderSize = HeaderSize + ConnIdSize

	InitSndMsgCryptoSize = 2 * PubKeySize // Two public keys
	InitRcvMsgCryptoSize = PubKeySize     // One public key

	MsgInitSndSize    = MsgHeaderSize + InitSndMsgCryptoSize + SnSize + MinPayloadSize + MacSize
	MinMsgInitRcvSize = MsgHeaderSize + InitRcvMsgCryptoSize + SnSize + MinPayloadSize + MacSize
	MinMsgSize        = MsgHeaderSize + SnSize + MinPayloadSize + MacSize
)

type MessageHeader struct {
	MsgType     MsgType
	ConnId      uint64
	PukKeyIdSnd *ecdh.PublicKey
	PukKeyEpSnd *ecdh.PublicKey
}

type Message struct {
	MessageHeader
	Sn           uint64
	PayloadRaw   []byte
	Payload      *Payload
	Fill         []byte
	SharedSecret []byte
}

// ************************************* Encoder *************************************

func EncodeWriteInitSnd(
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyIdSnd *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey,
	rawData []byte) (encData []byte, err error) {

	// Write the public key
	headerAndCryptoBuffer := make([]byte, MsgHeaderSize+InitSndMsgCryptoSize)

	// Write version
	headerAndCryptoBuffer[0] = VersionMagic

	// Write connection ID (pubKeyIdShortRcv XOR pubKeyIdShortSnd)
	connId := Uint64(pubKeyIdRcv.Bytes()) ^ Uint64(pubKeyIdSnd.Bytes())
	PutUint64(headerAndCryptoBuffer[HeaderSize:], connId)

	// Directly copy the sender's public key to the buffer following the connection ID
	copy(headerAndCryptoBuffer[MsgHeaderSize:], pubKeyIdSnd.Bytes())

	// Directly copy the ephemeral public key to the buffer following the sender's public key
	copy(headerAndCryptoBuffer[MsgHeaderSize+PubKeySize:], prvKeyEpSnd.PublicKey().Bytes())

	// Perform ECDH for initial encryption
	noPerfectForwardSharedSecret, err := prvKeyEpSnd.ECDH(pubKeyIdRcv)
	if err != nil {
		return nil, err
	}

	// Encrypt and write data
	return chainedEncrypt(1, noPerfectForwardSharedSecret, headerAndCryptoBuffer, rawData)
}

func EncodeWriteInitRcv(
	pubKeyIdRcv *ecdh.PublicKey,
	prvKeyIdSnd *ecdh.PrivateKey,
	pubKeyEpRcv *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey,
	rawData []byte) (encData []byte, err error) {

	// Preallocate buffer with capacity for header and crypto data
	headerAndCryptoBuffer := make([]byte, MsgHeaderSize+InitRcvMsgCryptoSize)

	// Write version
	headerAndCryptoBuffer[0] = VersionMagic

	// Write connection ID
	pubKeyIdSnd := prvKeyIdSnd.Public().(*ecdh.PublicKey)
	connId := Uint64(pubKeyIdRcv.Bytes()) ^ Uint64(pubKeyIdSnd.Bytes())
	PutUint64(headerAndCryptoBuffer[HeaderSize:], connId)

	// Directly copy the ephemeral public key to the buffer following the connection ID
	copy(headerAndCryptoBuffer[MsgHeaderSize:], prvKeyEpSnd.PublicKey().Bytes())

	// Perform ECDH for second encryption
	perfectForwardSharedSecret, err := prvKeyEpSnd.ECDH(pubKeyEpRcv)
	if err != nil {
		return nil, err
	}

	// Encrypt and write data
	return chainedEncrypt(1, perfectForwardSharedSecret, headerAndCryptoBuffer, rawData)
}

// EncodeWriteData encodes and writes a MSG packet.
func EncodeWriteData(
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyIdSnd *ecdh.PublicKey,
	sharedSecret []byte,
	sn uint64,
	rawData []byte) (encData []byte, err error) {

	// Preallocate buffer with capacity for header and connection ID
	headerBuffer := make([]byte, MsgHeaderSize)

	// Write version
	headerBuffer[0] = VersionMagic

	// Write connection ID
	connId := Uint64(pubKeyIdRcv.Bytes()) ^ Uint64(pubKeyIdSnd.Bytes())
	PutUint64(headerBuffer[HeaderSize:], connId)

	// Encrypt and write data
	return chainedEncrypt(sn, sharedSecret, headerBuffer, rawData)
}

func chainedEncrypt(sn uint64, sharedSecret []byte, headerAndCrypto []byte, rawData []byte) (fullMessage []byte, err error) {
	if len(rawData) < MinPayloadSize {
		return nil, errors.New("data too short, need at least 8 bytes to make the double encryption work")
	}

	if sn >= (1 << (SnSize * 8)) {
		return nil, fmt.Errorf("serial number is not a 48-bit value")
	}

	snSer := make([]byte, SnSize)
	PutUint48(snSer, sn)

	nonceDet := make([]byte, chacha20poly1305.NonceSize)
	for i := 0; i < chacha20poly1305.NonceSize; i++ {
		nonceDet[i] = sharedSecret[i] ^ snSer[i%SnSize]
	}

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, err
	}
	encData := aead.Seal(nil, nonceDet, rawData, headerAndCrypto)

	fullMessage = make([]byte, len(headerAndCrypto)+SnSize+len(encData))
	copy(fullMessage, headerAndCrypto)

	aeadSn, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		return nil, err
	}

	nonceRand := encData[0:24]
	encSn := aeadSn.Seal(nil, nonceRand, snSer, nil)
	copy(fullMessage[len(headerAndCrypto):], encSn[:SnSize])
	copy(fullMessage[len(headerAndCrypto)+SnSize:], encData)

	// Write the full message in one operation
	return fullMessage, nil
}

// ************************************* Decoder *************************************

func decodeConnId(encData []byte) (connId uint64, err error) {
	// Read the header byte and connId
	if len(encData) < MsgHeaderSize {
		return 0, errors.New("header needs to be at least 9 bytes")
	}

	header := encData[0]
	if header != VersionMagic {
		return 0, errors.New("unsupported magic version")
	}
	connId = Uint64(encData[HeaderSize:MsgHeaderSize])

	return connId, nil
}

func Decode(msgType MsgType, encData []byte, connId uint64, privKeyId *ecdh.PrivateKey, privKeyEp *ecdh.PrivateKey, sharedSecret []byte) (*Message, error) {
	mh := MessageHeader{
		MsgType: msgType,
		ConnId:  connId,
	}

	switch msgType {
	case InitSndMsgType:
		if len(encData) < MsgInitSndSize {
			return nil, errors.New("size is below minimum init")
		}
		return DecodeInit(encData, privKeyId, privKeyEp, mh)
	case InitRcvMsgType:
		if len(encData) < MinMsgInitRcvSize {
			return nil, errors.New("size is below minimum init reply")
		}
		return DecodeInitReply(encData, privKeyEp, mh)
	case DataMsgType:
		if len(encData) < MinMsgSize {
			return nil, errors.New("size is below minimum")
		}
		return DecodeMsg(encData, sharedSecret, mh)
	default:
		// Handle any unexpected message types if necessary.
		return nil, errors.New("unsupported message type")
	}
}

// DecodeInit decodes the message from a byte slice
func DecodeInit(
	encData []byte,
	prvKeyIdRcv *ecdh.PrivateKey,
	prvKeyEpRcv *ecdh.PrivateKey,
	mh MessageHeader) (*Message, error) {

	pukKeyIdSnd, err := ecdh.X25519().NewPublicKey(encData[MsgHeaderSize : MsgHeaderSize+PubKeySize])
	if err != nil {
		return nil, err
	}
	mh.PukKeyIdSnd = pukKeyIdSnd

	pubKeyEpSnd, err := ecdh.X25519().NewPublicKey(encData[MsgHeaderSize+PubKeySize : MsgHeaderSize+2*PubKeySize])
	if err != nil {
		return nil, err
	}
	mh.PukKeyEpSnd = pubKeyEpSnd

	noPerfectForwardSharedSecret, err := prvKeyIdRcv.ECDH(pubKeyEpSnd)
	if err != nil {
		return nil, err
	}

	sn, decryptedData, err := chainedDecrypt(
		noPerfectForwardSharedSecret,
		encData[0:MsgHeaderSize+InitSndMsgCryptoSize],
		encData[MsgHeaderSize+InitSndMsgCryptoSize:],
	)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := prvKeyEpRcv.ECDH(pubKeyEpSnd)
	if err != nil {
		return nil, err
	}

	return &Message{
		MessageHeader: mh,
		PayloadRaw:    decryptedData,
		SharedSecret:  sharedSecret,
		Sn:            sn,
	}, nil
}

// DecodeInitReply decodes an INIT_REPLY packet.
func DecodeInitReply(encData []byte, prvKeyEpSnd *ecdh.PrivateKey, mh MessageHeader) (*Message, error) {
	pubKeyEpRcv, err := ecdh.X25519().NewPublicKey(encData[MsgHeaderSize : MsgHeaderSize+PubKeySize])
	if err != nil {
		return nil, err
	}

	sharedSecret, err := prvKeyEpSnd.ECDH(pubKeyEpRcv)
	if err != nil {
		return nil, err
	}

	sn, decryptedData, err := chainedDecrypt(
		sharedSecret,
		encData[0:MsgHeaderSize+InitRcvMsgCryptoSize],
		encData[MsgHeaderSize+InitRcvMsgCryptoSize:],
	)
	if err != nil {
		return nil, err
	}

	return &Message{
		MessageHeader: mh,
		PayloadRaw:    decryptedData,
		SharedSecret:  sharedSecret,
		Sn:            sn,
	}, nil
}

// DecodeMsg decodes a MSG packet.
func DecodeMsg(encData []byte, sharedSecret []byte, mh MessageHeader) (*Message, error) {
	sn, decryptedData, err := chainedDecrypt(
		sharedSecret,
		encData[0:MsgHeaderSize],
		encData[MsgHeaderSize:],
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

func chainedDecrypt(sharedSecret []byte, header []byte, encData []byte) (sn uint64, decryptedData []byte, err error) {
	if len(encData) < 24 { // 8 bytes for encSn + 24 bytes for nonceRand
		return 0, nil, errors.New("encrypted data too short")
	}

	snSer := make([]byte, SnSize)

	encSn := encData[0:SnSize]
	encData = encData[SnSize:]
	nonceRand := encData[:24]
	snSer = openNoVerify(sharedSecret, nonceRand, encSn, snSer)

	nonceDet := make([]byte, 12)
	for i := 0; i < 12; i++ {
		nonceDet[i] = sharedSecret[i] ^ snSer[i%SnSize]
	}

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return 0, nil, err
	}

	decryptedData, err = aead.Open(nil, nonceDet, encData, header)
	if err != nil {
		return 0, nil, err
	}

	sn = Uint48(snSer)
	return sn, decryptedData, nil
}

// inspired by: https://github.com/golang/crypto/blob/master/chacha20poly1305/chacha20poly1305_generic.go
func openNoVerify(sharedSecret []byte, nonce []byte, encoded []byte, snSer []byte) []byte {
	s, _ := chacha20.NewUnauthenticatedCipher(sharedSecret, nonce)
	s.SetCounter(1) // Set the counter to 1, skipping 32 bytes

	// Decrypt the ciphertext
	s.XORKeyStream(snSer, encoded)

	return snSer
}
