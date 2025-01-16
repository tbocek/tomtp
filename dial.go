package tomtp

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"strings"
)

type DialOption struct {
	streamId    uint32
	prvKeyEp    *ecdh.PrivateKey
	pubKeyEpRcv *ecdh.PublicKey
}

type DialFunc func(*DialOption)

func WithStreamId(streamId uint32) DialFunc {
	return func(c *DialOption) {
		c.streamId = streamId
	}
}

func WithPrivKeyEp(privKeyEp *ecdh.PrivateKey) DialFunc {
	return func(c *DialOption) {
		c.prvKeyEp = privKeyEp
	}
}

func WithPubKeyEpRcv(pubKeyEpRcv *ecdh.PublicKey) DialFunc {
	return func(c *DialOption) {
		c.pubKeyEpRcv = pubKeyEpRcv
	}
}

func (l *Listener) DialString(remoteAddrString string, pubKeyIdRcvHex string, options ...DialFunc) (*Stream, error) {
	remoteAddr, err := net.ResolveUDPAddr("udp", remoteAddrString)
	if err != nil {
		slog.Error(
			"error resolving remote address",
			slog.Any("error", err),
			slog.String("address", remoteAddrString))
		return nil, err
	}

	if strings.HasPrefix(pubKeyIdRcvHex, "0x") {
		pubKeyIdRcvHex = strings.Replace(pubKeyIdRcvHex, "0x", "", 1)
	}

	b, err := hex.DecodeString(pubKeyIdRcvHex)
	if err != nil {
		slog.Error(
			"error decoding hex string",
			slog.Any("error", err),
			slog.String("hex", pubKeyIdRcvHex))
		return nil, err
	}

	pubKeyIdRcv, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		slog.Error(
			"error decoding public key",
			slog.Any("error", err),
			slog.String("hex", pubKeyIdRcvHex))
		return nil, err
	}

	return l.Dial(remoteAddr, pubKeyIdRcv, options...)
}

func (l *Listener) Dial(remoteAddr net.Addr, pubKeyIdRcv *ecdh.PublicKey, options ...DialFunc) (*Stream, error) {
	lOpts := fillDialOpts(options...)

	if lOpts.prvKeyEp == nil {
		var err error
		lOpts.prvKeyEp, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			slog.Error("error in rnd", slog.Any("error", err))
			return nil, err
		}
	}

	c, err := l.newConn(remoteAddr, pubKeyIdRcv, lOpts.prvKeyEp, lOpts.pubKeyEpRcv, true)
	if err != nil {
		slog.Error("cannot create new connection", slog.Any("error", err))
		return nil, err
	}
	return c.NewStreamSnd(lOpts.streamId)
}

func fillDialOpts(options ...DialFunc) *DialOption {
	lOpts := &DialOption{
		streamId: 0,
		prvKeyEp: nil,
	}
	for _, opt := range options {
		opt(lOpts)
	}
	return lOpts
}
