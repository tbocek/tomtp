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
	VersionMagic uint8 = 33

	InitS0MsgType MsgType = iota
	InitR0S1R1MsgType
	DataMsgType
	UnknownType
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

type Message struct {
	MsgType      MsgType
	SnConn       uint64
	PayloadRaw   []byte
	Payload      *Payload
	Fill         []byte
	SharedSecret []byte
}

// ************************************* Encoder *************************************

func EncodeWriteInitS0(
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyIdSnd *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey,
	rawData []byte) (encData []byte, err error) {

	// Write the public key
	headerAndCryptoBuffer := make([]byte, MsgHeaderSize+InitSndMsgCryptoSize)

	// Write version
	headerAndCryptoBuffer[0] = (VersionMagic << 2) | uint8(InitS0MsgType)

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
	return chainedEncrypt(0, true, noPerfectForwardSharedSecret, headerAndCryptoBuffer, rawData)
}

func EncodeWriteInitR0S1R1(
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyIdSnd *ecdh.PublicKey,
	pubKeyEpRcv *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey,
	rawData []byte) (encData []byte, err error) {

	// Preallocate buffer with capacity for header and crypto data
	headerAndCryptoBuffer := make([]byte, MsgHeaderSize+InitRcvMsgCryptoSize)

	// Write version
	headerAndCryptoBuffer[0] = (VersionMagic << 2) | uint8(InitR0S1R1MsgType)

	// Write connection ID
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
	return chainedEncrypt(0, false, perfectForwardSharedSecret, headerAndCryptoBuffer, rawData)
}

func EncodeWriteData(
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyIdSnd *ecdh.PublicKey,
	isSender bool,
	sharedSecret []byte,
	sn uint64,
	rawData []byte) (encData []byte, err error) {

	// Preallocate buffer with capacity for header and connection ID
	headerBuffer := make([]byte, MsgHeaderSize)

	// Write version
	headerBuffer[0] = (VersionMagic << 2) | uint8(DataMsgType)

	// Write connection ID
	connId := Uint64(pubKeyIdRcv.Bytes()) ^ Uint64(pubKeyIdSnd.Bytes())
	PutUint64(headerBuffer[HeaderSize:], connId)

	// Encrypt and write data
	return chainedEncrypt(sn, isSender, sharedSecret, headerBuffer, rawData)
}

func chainedEncrypt(snConn uint64, isSender bool, sharedSecret []byte, headerAndCrypto []byte, rawData []byte) (fullMessage []byte, err error) {
	if len(rawData) < MinPayloadSize {
		return nil, errors.New("data too short, need at least 8 bytes to make the double encryption work")
	}

	if snConn >= (1 << (SnSize * 8)) {
		return nil, fmt.Errorf("serial number is not a 48-bit value")
	}

	snConnSer := make([]byte, SnSize)
	PutUint48(snConnSer, snConn)
	nonceDet := make([]byte, chacha20poly1305.NonceSize)

	// If sender, place in first half; if receiver, place in second half
	offset := 0
	if !isSender {
		offset = SnSize
	}
	copy(nonceDet[offset:], snConnSer)

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
	encSn := aeadSn.Seal(nil, nonceRand, snConnSer, nil)
	copy(fullMessage[len(headerAndCrypto):], encSn[:SnSize])
	copy(fullMessage[len(headerAndCrypto)+SnSize:], encData)

	// Write the full message in one operation
	return fullMessage, nil
}

// ************************************* Decoder *************************************

func decodeConnId(encData []byte) (connId uint64, msgType MsgType, err error) {
	// Read the header byte and connId
	if len(encData) < MsgHeaderSize {
		return 0, UnknownType, errors.New("header needs to be at least 9 bytes")
	}

	header := encData[0]
	if header>>2 != VersionMagic {
		return 0, UnknownType, errors.New("unsupported magic version")
	}

	connId = Uint64(encData[HeaderSize:MsgHeaderSize])

	return connId, MsgType(header & 0x3), nil
}

// DecodeInitS0 the recipient decodes this
func DecodeInitS0(
	encData []byte,
	prvKeyIdRcv *ecdh.PrivateKey,
	prvKeyEpRcv *ecdh.PrivateKey) (pubKeyIdSnd *ecdh.PublicKey, pubKeyEpSnd *ecdh.PublicKey, m *Message, err error) {

	if len(encData) < MsgInitSndSize {
		return nil, nil, nil, errors.New("size is below minimum init")
	}

	pubKeyIdSnd, err = ecdh.X25519().NewPublicKey(encData[MsgHeaderSize : MsgHeaderSize+PubKeySize])
	if err != nil {
		return nil, nil, nil, err
	}

	pubKeyEpSnd, err = ecdh.X25519().NewPublicKey(encData[MsgHeaderSize+PubKeySize : MsgHeaderSize+2*PubKeySize])
	if err != nil {
		return nil, nil, nil, err
	}

	noPerfectForwardSharedSecret, err := prvKeyIdRcv.ECDH(pubKeyEpSnd)

	if err != nil {
		return nil, nil, nil, err
	}

	snConn, decryptedData, err := chainedDecrypt(
		false,
		noPerfectForwardSharedSecret,
		encData[0:MsgHeaderSize+InitSndMsgCryptoSize],
		encData[MsgHeaderSize+InitSndMsgCryptoSize:],
	)
	if err != nil {
		return nil, nil, nil, err
	}

	sharedSecret, err := prvKeyEpRcv.ECDH(pubKeyEpSnd)

	if err != nil {
		return nil, nil, nil, err
	}

	return pubKeyIdSnd, pubKeyEpSnd, &Message{
		MsgType:      InitS0MsgType,
		PayloadRaw:   decryptedData,
		SharedSecret: sharedSecret,
		SnConn:       snConn,
	}, nil
}

// DecodeInitR0S1R1 is decoded by the sender
func DecodeInitR0S1R1(
	encData []byte,
	prvKeyEpSnd *ecdh.PrivateKey) (*Message, error) {

	if len(encData) < MinMsgInitRcvSize {
		return nil, errors.New("size is below minimum init reply")
	}

	pubKeyEpRcv, err := ecdh.X25519().NewPublicKey(encData[MsgHeaderSize : MsgHeaderSize+PubKeySize])
	if err != nil {
		return nil, err
	}

	sharedSecret, err := prvKeyEpSnd.ECDH(pubKeyEpRcv)
	if err != nil {
		return nil, err
	}

	snConn, decryptedData, err := chainedDecrypt(
		true,
		sharedSecret,
		encData[0:MsgHeaderSize+InitRcvMsgCryptoSize],
		encData[MsgHeaderSize+InitRcvMsgCryptoSize:],
	)
	if err != nil {
		return nil, err
	}

	return &Message{
		MsgType:      InitR0S1R1MsgType,
		PayloadRaw:   decryptedData,
		SharedSecret: sharedSecret,
		SnConn:       snConn,
	}, nil
}

func DecodeMsg(
	encData []byte,
	isSender bool,
	sharedSecret []byte) (*Message, error) {

	if len(encData) < MinMsgSize {
		return nil, errors.New("size is below minimum")
	}

	snConn, decryptedData, err := chainedDecrypt(
		isSender,
		sharedSecret,
		encData[0:MsgHeaderSize],
		encData[MsgHeaderSize:],
	)
	if err != nil {
		return nil, err
	}

	return &Message{
		MsgType:    DataMsgType,
		PayloadRaw: decryptedData,
		SnConn:     snConn,
	}, nil
}

func chainedDecrypt(isSender bool, sharedSecret []byte, header []byte, encData []byte) (snConn uint64, decryptedData []byte, err error) {
	if len(encData) < 24 { // 8 bytes for encSn + 24 bytes for nonceRand
		return 0, nil, errors.New("encrypted data too short")
	}

	snConnSer := make([]byte, SnSize)

	encSn := encData[0:SnSize]
	encData = encData[SnSize:]
	nonceRand := encData[:24]
	snConnSer, err = openNoVerify(sharedSecret, nonceRand, encSn, snConnSer)
	if err != nil {
		return 0, nil, err
	}

	nonceDet := make([]byte, chacha20poly1305.NonceSize)

	offset := 0
	if isSender {
		offset = SnSize
	}
	copy(nonceDet[offset:], snConnSer)

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return 0, nil, err
	}

	decryptedData, err = aead.Open(nil, nonceDet, encData, header)
	if err != nil {
		return 0, nil, err
	}

	snConn = Uint48(snConnSer)
	return snConn, decryptedData, nil
}

// inspired by: https://github.com/golang/crypto/blob/master/chacha20poly1305/chacha20poly1305_generic.go
func openNoVerify(sharedSecret []byte, nonce []byte, encoded []byte, snSer []byte) ([]byte, error) {
	s, err := chacha20.NewUnauthenticatedCipher(sharedSecret, nonce)
	if err != nil {
		return nil, err
	}
	s.SetCounter(1) // Set the counter to 1, skipping 32 bytes

	// Decrypt the ciphertext
	s.XORKeyStream(snSer, encoded)

	return snSer, nil
}
