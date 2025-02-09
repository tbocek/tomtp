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
	InitS0MsgType MsgType = iota
	InitR0MsgType
	Data0MsgType
	DataMsgType

	VersionMagic uint8 = 33
)

const (
	MacSize = 16
	SnSize  = 6 // Sequence number Size is 48bit / 6 bytes
	//MinPayloadSize is the minimum payload Size in bytes. We need at least 8 bytes as
	// 8 + the MAC Size (16 bytes) is 24 bytes, which is used as the input for
	// sealing with chacha20poly1305.NewX().
	MinPayloadSize = 9
	PubKeySize     = 32

	HeaderSize    = 1
	ConnIdSize    = 8
	MsgHeaderSize = HeaderSize + ConnIdSize

	InitS0CryptoSize = 3 * PubKeySize // Three public keys
	InitR0CryptoSize = 2 * PubKeySize // Two public key
	Data0CryptoSize  = PubKeySize     // One public key for DATA_0

	MsgInitFillLenSize = 2
	MsgInitSndSize     = MsgHeaderSize + InitS0CryptoSize + SnSize + MsgInitFillLenSize + MacSize
	MinMsgInitRcvSize  = MsgHeaderSize + InitR0CryptoSize + SnSize + MacSize
	MinMsgData0Size    = MsgHeaderSize + Data0CryptoSize + SnSize + MacSize
	MinMsgSize         = MsgHeaderSize + SnSize + MacSize
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
	prvKeyEpSndRollover *ecdh.PrivateKey,
	rawData []byte) (encData []byte, err error) {

	if len(rawData) < MinPayloadSize {
		return nil, errors.New("packet data too short")
	}

	// Write the public key
	headerAndCryptoBuffer := make([]byte, MsgHeaderSize+InitS0CryptoSize)

	// Write version
	headerAndCryptoBuffer[0] = (VersionMagic << 2) | uint8(InitS0MsgType)

	// Write connection ID (pubKeyIdShortRcv XOR pubKeyIdShortSnd)
	connId := Uint64(pubKeyIdRcv.Bytes()) ^ Uint64(pubKeyIdSnd.Bytes())
	PutUint64(headerAndCryptoBuffer[HeaderSize:], connId)

	// Directly copy the sender's public key to the buffer following the connection ID
	copy(headerAndCryptoBuffer[MsgHeaderSize:], pubKeyIdSnd.Bytes())

	// Directly copy the ephemeral public key to the buffer following the sender's public key
	copy(headerAndCryptoBuffer[MsgHeaderSize+PubKeySize:], prvKeyEpSnd.PublicKey().Bytes())

	// Copy sender's ephemeral rollover public key
	copy(headerAndCryptoBuffer[MsgHeaderSize+2*PubKeySize:], prvKeyEpSndRollover.PublicKey().Bytes())

	// Perform ECDH for initial encryption
	noPerfectForwardSharedSecret, err := prvKeyEpSnd.ECDH(pubKeyIdRcv)

	if err != nil {
		return nil, err
	}

	// Encrypt and write data
	fillLen := uint16(startMtu - MsgInitSndSize - len(rawData))

	// Create payload with filler length and filler if needed
	payloadWithFiller := make([]byte, 2+int(fillLen)+len(rawData)) // +2 for filler length
	// Add filler length
	PutUint16(payloadWithFiller, fillLen)
	// After the filler, copy the data
	copy(payloadWithFiller[2+int(fillLen):], rawData)

	return chainedEncrypt(0, true, noPerfectForwardSharedSecret, headerAndCryptoBuffer, payloadWithFiller)
}

func EncodeWriteInitR0(
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyIdSnd *ecdh.PublicKey,
	pubKeyEpRcv *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey,
	prvKeyEpSndRollover *ecdh.PrivateKey,
	rawData []byte) (encData []byte, err error) {

	if len(rawData) < MinPayloadSize {
		return nil, errors.New("packet data too short")
	}

	// Write the public key
	headerAndCryptoBuffer := make([]byte, MsgHeaderSize+InitR0CryptoSize)

	// Write version
	headerAndCryptoBuffer[0] = (VersionMagic << 2) | uint8(InitR0MsgType)

	// Write connection ID (pubKeyIdShortRcv XOR pubKeyIdShortSnd)
	connId := Uint64(pubKeyIdRcv.Bytes()) ^ Uint64(pubKeyIdSnd.Bytes())
	PutUint64(headerAndCryptoBuffer[HeaderSize:], connId)

	// Directly copy the ephemeral public key to the buffer following the sender's public key
	copy(headerAndCryptoBuffer[MsgHeaderSize:], prvKeyEpSnd.PublicKey().Bytes())

	// Copy sender's ephemeral rollover public key
	copy(headerAndCryptoBuffer[MsgHeaderSize+PubKeySize:], prvKeyEpSndRollover.PublicKey().Bytes())

	// Perform ECDH for initial encryption
	perfectForwardSharedSecret, err := prvKeyEpSnd.ECDH(pubKeyEpRcv)

	if err != nil {
		return nil, err
	}

	// Encrypt and write data
	return chainedEncrypt(0, true, perfectForwardSharedSecret, headerAndCryptoBuffer, rawData)
}

func EncodeWriteData0(
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyIdSnd *ecdh.PublicKey,
	isSender bool,
	pubKeyEpRcv *ecdh.PublicKey,
	prvKeyEpSndRollover *ecdh.PrivateKey,
	rawData []byte) (encData []byte, err error) {

	if len(rawData) < MinPayloadSize {
		return nil, errors.New("packet data too short")
	}

	// Preallocate buffer with capacity for header and crypto data
	headerAndCryptoBuffer := make([]byte, MsgHeaderSize+Data0CryptoSize)

	// Write version
	headerAndCryptoBuffer[0] = (VersionMagic << 2) | uint8(Data0MsgType)

	// Write connection ID
	connId := Uint64(pubKeyIdRcv.Bytes()) ^ Uint64(pubKeyIdSnd.Bytes())
	PutUint64(headerAndCryptoBuffer[HeaderSize:], connId)

	// Directly copy the ephemeral public key to the buffer following the connection ID
	copy(headerAndCryptoBuffer[MsgHeaderSize:], prvKeyEpSndRollover.PublicKey().Bytes())

	// Perform ECDH for second encryption
	perfectForwardSharedSecret, err := prvKeyEpSndRollover.ECDH(pubKeyEpRcv)
	if err != nil {
		return nil, err
	}

	// Encrypt and write data
	return chainedEncrypt(0, isSender, perfectForwardSharedSecret, headerAndCryptoBuffer, rawData)
}

func EncodeWriteData(
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyIdSnd *ecdh.PublicKey,
	isSender bool,
	sharedSecret []byte,
	sn uint64,
	rawData []byte) (encData []byte, err error) {

	if len(rawData) < MinPayloadSize {
		return nil, errors.New("packet data too short")
	}

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
	if len(rawData) < 8 {
		return nil, errors.New("data too short")
	}
	if snConn >= (1 << (SnSize * 8)) {
		return nil, fmt.Errorf("serial number is not a 48-bit value")
	}

	// Rest remains zero filled

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
		return 0, Data0MsgType, errors.New("header needs to be at least 9 bytes")
	}

	header := encData[0]
	versionMagic := header >> 2
	// Extract message type using mask
	msgType = MsgType(header & 0x03)

	if versionMagic != VersionMagic {
		return 0, Data0MsgType, errors.New("unsupported magic version")
	}

	connId = Uint64(encData[HeaderSize:MsgHeaderSize])

	return connId, msgType, nil
}

// DecodeInitS0 the recipient decodes this
func DecodeInitS0(
	encData []byte,
	prvKeyIdRcv *ecdh.PrivateKey,
	prvKeyEpRcv *ecdh.PrivateKey) (
	pubKeyIdSnd *ecdh.PublicKey,
	pubKeyEpSnd *ecdh.PublicKey,
	pubKeyEpSndRollover *ecdh.PublicKey,
	m *Message,
	err error) {

	if len(encData) < MsgInitSndSize {
		return nil, nil, nil, nil, errors.New("Size is below minimum init")
	}

	pubKeyIdSnd, err = ecdh.X25519().NewPublicKey(encData[MsgHeaderSize : MsgHeaderSize+PubKeySize])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	pubKeyEpSnd, err = ecdh.X25519().NewPublicKey(encData[MsgHeaderSize+PubKeySize : MsgHeaderSize+2*PubKeySize])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	pubKeyEpSndRollover, err = ecdh.X25519().NewPublicKey(
		encData[MsgHeaderSize+2*PubKeySize : MsgHeaderSize+3*PubKeySize])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	noPerfectForwardSharedSecret, err := prvKeyIdRcv.ECDH(pubKeyEpSnd)

	if err != nil {
		return nil, nil, nil, nil, err
	}

	snConn, decryptedData, err := chainedDecrypt(
		false,
		noPerfectForwardSharedSecret,
		encData[0:MsgHeaderSize+InitS0CryptoSize],
		encData[MsgHeaderSize+InitS0CryptoSize:],
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	sharedSecret, err := prvKeyEpRcv.ECDH(pubKeyEpSnd)

	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Extract actual data - Remove filler_length and filler
	fillerLen := Uint16(decryptedData)
	actualData := decryptedData[2+int(fillerLen):]

	return pubKeyIdSnd, pubKeyEpSnd, pubKeyEpSndRollover, &Message{
		MsgType:      InitS0MsgType,
		PayloadRaw:   actualData,
		SharedSecret: sharedSecret,
		SnConn:       snConn,
	}, nil
}

// DecodeInitR0 is decoded by the sender
func DecodeInitR0(
	encData []byte,
	prvKeyEpSnd *ecdh.PrivateKey) (
	pubKeyEpRcv *ecdh.PublicKey,
	pubKeyEpRcvRollover *ecdh.PublicKey,
	m *Message,
	err error) {

	if len(encData) < MinMsgInitRcvSize {
		return nil, nil, nil, errors.New("Size is below minimum init reply")
	}

	pubKeyEpRcv, err = ecdh.X25519().NewPublicKey(encData[MsgHeaderSize : MsgHeaderSize+PubKeySize])
	if err != nil {
		return nil, nil, nil, err
	}

	pubKeyEpRcvRollover, err = ecdh.X25519().NewPublicKey(
		encData[MsgHeaderSize+PubKeySize : MsgHeaderSize+2*PubKeySize])
	if err != nil {
		return nil, nil, nil, err
	}

	sharedSecret, err := prvKeyEpSnd.ECDH(pubKeyEpRcv)
	if err != nil {
		return nil, nil, nil, err
	}

	snConn, decryptedData, err := chainedDecrypt(
		true,
		sharedSecret,
		encData[0:MsgHeaderSize+InitR0CryptoSize],
		encData[MsgHeaderSize+InitR0CryptoSize:],
	)
	if err != nil {
		return nil, nil, nil, err
	}

	return pubKeyEpRcv, pubKeyEpRcvRollover, &Message{
		MsgType:      InitR0MsgType,
		PayloadRaw:   decryptedData,
		SharedSecret: sharedSecret,
		SnConn:       snConn,
	}, nil
}

func DecodeData0(
	encData []byte,
	prvKeyEpSnd *ecdh.PrivateKey) (
	pubKeyEpRollover *ecdh.PublicKey, m *Message, err error) {

	if len(encData) < MinMsgData0Size {
		return nil, nil, errors.New("Size is below minimum Data0")
	}

	pubKeyEpRollover, err = ecdh.X25519().NewPublicKey(
		encData[MsgHeaderSize : MsgHeaderSize+PubKeySize])
	if err != nil {
		return nil, nil, err
	}

	sharedSecret, err := prvKeyEpSnd.ECDH(pubKeyEpRollover)
	if err != nil {
		return nil, nil, err
	}

	snConn, decryptedData, err := chainedDecrypt(
		false,
		sharedSecret,
		encData[0:MsgHeaderSize+Data0CryptoSize],
		encData[MsgHeaderSize+Data0CryptoSize:],
	)
	if err != nil {
		return nil, nil, err
	}

	return pubKeyEpRollover, &Message{
		MsgType:      Data0MsgType,
		PayloadRaw:   decryptedData,
		SharedSecret: sharedSecret,
		SnConn:       snConn,
	}, nil
}

func DecodeData(
	encData []byte,
	isSender bool,
	sharedSecret []byte) (*Message, error) {

	if len(encData) < MinMsgSize {
		return nil, errors.New("Size is below minimum")
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
