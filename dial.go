package tomtp

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"strings"
)

const maxIdleMillis = uint64(200)

type DialOption struct {
	streamId    uint32
	prvKeyEp    *ecdh.PrivateKey
	pubKeyEpRcv *ecdh.PublicKey
}

type OptionFunc func(*DialOption)

func WithStreamId(streamId uint32) OptionFunc {
	return func(c *DialOption) {
		c.streamId = streamId
	}
}

func WithPrivKeyEp(privKeyEp *ecdh.PrivateKey) OptionFunc {
	return func(c *DialOption) {
		c.prvKeyEp = privKeyEp
	}
}

func WithPubKeyEpRcv(pubKeyEpRcv *ecdh.PublicKey) OptionFunc {
	return func(c *DialOption) {
		c.pubKeyEpRcv = pubKeyEpRcv
	}
}

func (l *Listener) Dial(remoteAddrString string, pubKeyIdRcvHex string, options ...OptionFunc) (*Stream, error) {
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

	return l.DialTP(remoteAddr, pubKeyIdRcv, options...)
}

func fillDialOpts(options ...OptionFunc) *DialOption {
	lOpts := &DialOption{
		streamId: 0,
		prvKeyEp: nil,
	}
	for _, opt := range options {
		opt(lOpts)
	}
	return lOpts
}

func (l *Listener) DialTP(remoteAddr net.Addr, pubKeyIdRcv *ecdh.PublicKey, options ...OptionFunc) (*Stream, error) {
	lOpts := fillDialOpts(options...)

	if lOpts.prvKeyEp == nil {
		var err error
		lOpts.prvKeyEp, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			slog.Error("error in rnd", slog.Any("error", err))
			return nil, err
		}
	}

	c, err := l.newConn(remoteAddr, pubKeyIdRcv, lOpts.prvKeyEp, lOpts.pubKeyEpRcv)
	if err != nil {
		slog.Error("cannot create new connection", slog.Any("error", err))
		return nil, err
	}
	return c.NewStream(lOpts.streamId)
}
