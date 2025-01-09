package tomtp

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

type MsgType uint8

// Message structure sizes
const (
	VersionMagic uint8 = 77

	InitSnd MsgType = iota
	InitRcv
	Msg

	MacSize    = 16
	SnSize     = 6
	MinPayload = 8
	pubKeySize = 32

	// Header components
	headerSize = 1 // Version + type
	connIdSize = 8
	MsgHeader  = headerSize + connIdSize

	// Crypto sections
	cryptoInitSize = pubKeySize + pubKeySize // Two public keys
	cryptoRcvSize  = pubKeySize              // One public key

	// Total message sizes
	MsgInitSndHeaderAndCrypto = cryptoInitSize + MsgHeader
	MsgInitRcvHeaderAndCrypto = cryptoRcvSize + MsgHeader
	MsgInitSndSize            = MsgInitSndHeaderAndCrypto + SnSize + MinPayload + MacSize
	MinMsgInitRcvSize         = MsgInitRcvHeaderAndCrypto + SnSize + MinPayload + MacSize
	MinMsgSize                = MsgHeader + SnSize + MinPayload + MacSize
)

type MessageHeader struct {
	MsgType     MsgType
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

// ************************************* Encoder *************************************

func EncodeWriteInit(
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyIdSnd *ecdh.PublicKey,
	privKeyEpSnd *ecdh.PrivateKey,
	rawData []byte) (encData []byte, err error) {

	// Write the public key
	headerAndCryptoBuffer := make([]byte, MsgInitSndHeaderAndCrypto)

	// Write version
	headerAndCryptoBuffer[0] = VersionMagic

	// Write connection ID (pubKeyIdShortRcv XOR pubKeyIdShortSnd)
	connId := binary.LittleEndian.Uint64(pubKeyIdRcv.Bytes()) ^ binary.LittleEndian.Uint64(pubKeyIdSnd.Bytes())
	binary.LittleEndian.PutUint64(headerAndCryptoBuffer[headerSize:], connId)

	// Directly copy the sender's public key to the buffer following the connection ID
	copy(headerAndCryptoBuffer[MsgHeader:], pubKeyIdSnd.Bytes())

	// Directly copy the ephemeral public key to the buffer following the sender's public key
	copy(headerAndCryptoBuffer[MsgHeader+pubKeySize:], privKeyEpSnd.PublicKey().Bytes())

	// Perform ECDH for initial encryption
	noPerfectForwardSecret, err := privKeyEpSnd.ECDH(pubKeyIdRcv)
	if err != nil {
		return nil, err
	}

	// Encrypt and write data
	return chainedEncrypt(1, noPerfectForwardSecret, headerAndCryptoBuffer, rawData)
}

func EncodeWriteInitReply(
	pubKeyIdRcv *ecdh.PublicKey,
	privKeyIdSnd *ecdh.PrivateKey,
	pubKeyEpRcv *ecdh.PublicKey,
	privKeyEpSnd *ecdh.PrivateKey,
	rawData []byte) (encData []byte, err error) {

	// Preallocate buffer with capacity for header and crypto data
	headerAndCryptoBuffer := make([]byte, MsgInitRcvHeaderAndCrypto)

	// Write version
	headerAndCryptoBuffer[0] = VersionMagic

	// Write connection ID
	pubKeyIdSnd := privKeyIdSnd.Public().(*ecdh.PublicKey)
	connId := binary.LittleEndian.Uint64(pubKeyIdRcv.Bytes()) ^ binary.LittleEndian.Uint64(pubKeyIdSnd.Bytes())
	binary.LittleEndian.PutUint64(headerAndCryptoBuffer[headerSize:], connId)

	// Directly copy the ephemeral public key to the buffer following the connection ID
	copy(headerAndCryptoBuffer[MsgHeader:], privKeyEpSnd.PublicKey().Bytes())

	// Perform ECDH for second encryption
	perfectForwardSecret, err := privKeyEpSnd.ECDH(pubKeyEpRcv)
	if err != nil {
		return nil, err
	}

	// Encrypt and write data
	return chainedEncrypt(1, perfectForwardSecret, headerAndCryptoBuffer, rawData)
}

// EncodeWriteMsg encodes and writes a MSG packet.
func EncodeWriteMsg(
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyIdSnd *ecdh.PublicKey,
	sharedSecret []byte,
	sn uint64,
	rawData []byte) (encData []byte, err error) {

	// Preallocate buffer with capacity for header and connection ID
	headerBuffer := make([]byte, MsgHeader)

	// Write version
	headerBuffer[0] = VersionMagic

	// Write connection ID
	connId := binary.LittleEndian.Uint64(pubKeyIdRcv.Bytes()) ^ binary.LittleEndian.Uint64(pubKeyIdSnd.Bytes())
	binary.LittleEndian.PutUint64(headerBuffer[headerSize:], connId)

	// Encrypt and write data
	return chainedEncrypt(sn, sharedSecret, headerBuffer, rawData)
}

func chainedEncrypt(sn uint64, sharedSecret []byte, headerAndCrypto []byte, data []byte) (fullMessage []byte, err error) {
	if len(data) < MinPayload {
		return nil, errors.New("data too short, need at least 8 bytes to make the double encryption work")
	}

	if sn >= (1 << (SnSize * 8)) {
		return nil, fmt.Errorf("serial number is not a 48-bit value")
	}

	snSer := make([]byte, SnSize)
	PutUint48(snSer, sn /*&0xFFFFFFFFFFFF*/)

	nonceDet := make([]byte, chacha20poly1305.NonceSize)
	for i := 0; i < chacha20poly1305.NonceSize; i++ {
		nonceDet[i] = sharedSecret[i] ^ snSer[i%SnSize]
	}

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, err
	}
	encData := aead.Seal(nil, nonceDet, data, headerAndCrypto)

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

func decodeConnId(b []byte) (header byte, connId uint64, err error) {
	// Read the header byte and connId
	if len(b) < MsgHeader {
		return 0, 0, errors.New("header needs to be at least 9 bytes")
	}

	header = b[0]
	connId = binary.LittleEndian.Uint64(b[headerSize:MsgHeader])

	return header, connId, nil
}

func Decode(msgType MsgType, b []byte, header byte, connId uint64, privKeyId *ecdh.PrivateKey, privKeyEp *ecdh.PrivateKey, sharedSecret []byte) (*Message, error) {

	if header != VersionMagic {
		return nil, errors.New("unsupported crypto version")
	}

	mh := MessageHeader{
		MsgType: msgType,
		ConnId:  connId,
	}

	switch msgType {
	case InitSnd:
		if len(b) < MsgInitSndSize { //needs to be the full size of the packet
			return nil, errors.New("size is below minimum init")
		}
		return DecodeInit(b, privKeyId, privKeyEp, mh)
	case InitRcv:
		if len(b) < MinMsgInitRcvSize {
			return nil, errors.New("size is below minimum init reply")
		}
		return DecodeInitReply(b, privKeyEp, mh)
	case Msg:
		if len(b) < MinMsgSize {
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

	pukKeyIdSnd, err := ecdh.X25519().NewPublicKey(raw[MsgHeader : MsgHeader+pubKeySize])
	if err != nil {
		return nil, err
	}
	mh.PukKeyIdSnd = pukKeyIdSnd

	pubKeyEpSnd, err := ecdh.X25519().NewPublicKey(raw[MsgHeader+pubKeySize : MsgHeader+pubKeySize+pubKeySize])
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
		raw[0:MsgInitSndHeaderAndCrypto],
		raw[MsgInitSndHeaderAndCrypto:],
	)
	if err != nil {
		return nil, err
	}

	secret, err := privKeyEpRcv.ECDH(pubKeyEpSnd)
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

// DecodeInitReply decodes an INIT_REPLY packet.
func DecodeInitReply(raw []byte, privKeyEpSnd *ecdh.PrivateKey, mh MessageHeader) (*Message, error) {
	pubKeyEpRcv, err := ecdh.X25519().NewPublicKey(raw[MsgHeader : MsgHeader+pubKeySize])
	if err != nil {
		return nil, err
	}

	secret, err := privKeyEpSnd.ECDH(pubKeyEpRcv)
	if err != nil {
		return nil, err
	}

	sn, decryptedData, err := chainedDecrypt(
		secret,
		raw[0:MsgInitRcvHeaderAndCrypto],
		raw[MsgInitRcvHeaderAndCrypto:],
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
		raw[0:MsgHeader],
		raw[MsgHeader:],
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

func chainedDecrypt(sharedSecret []byte, header []byte, encData []byte) (sn uint64, decoded []byte, err error) {
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

	data, err := aead.Open(nil, nonceDet, encData, header)
	if err != nil {
		return 0, nil, err
	}

	sn = Uint48(snSer)
	return sn, data, nil
}

// inspired by: https://github.com/golang/crypto/blob/master/chacha20poly1305/chacha20poly1305_generic.go
func openNoVerify(sharedSecret []byte, nonce []byte, encoded []byte, snSer []byte) []byte {
	s, _ := chacha20.NewUnauthenticatedCipher(sharedSecret, nonce)
	s.SetCounter(1) // Set the counter to 1, skipping 32 bytes

	// Decrypt the ciphertext
	s.XORKeyStream(snSer, encoded)

	return snSer
}
