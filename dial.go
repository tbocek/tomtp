package tomtp

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"strings"
)

type DialOption struct {
	streamId    uint32
	noLoop      bool
	privKeyEp   *ecdh.PrivateKey
	pubKeyEpRcv *ecdh.PublicKey
}

type OptionFunc func(*DialOption)

func WithStreamId(streamId uint32) OptionFunc {
	return func(c *DialOption) {
		c.streamId = streamId
	}
}

func WithNoLoop() OptionFunc {
	return func(c *DialOption) {
		c.noLoop = true
	}
}

func WithPrivKeyEp(privKeyEp *ecdh.PrivateKey) OptionFunc {
	return func(c *DialOption) {
		c.privKeyEp = privKeyEp
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
	pubKeyIdRcv := ed25519.PublicKey(b)

	return l.DialTP(remoteAddr, pubKeyIdRcv, options...)
}

func (l *Listener) DialTP(remoteAddr *net.UDPAddr, pubKeyIdRcv ed25519.PublicKey, options ...OptionFunc) (*Stream, error) {
	lOpts := &DialOption{
		streamId:  0,
		noLoop:    false,
		privKeyEp: nil,
	}
	for _, opt := range options {
		opt(lOpts)
	}
	if lOpts.privKeyEp == nil {
		var err error
		lOpts.privKeyEp, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			slog.Error("error in rnd", slog.Any("error", err))
			return nil, err
		}
	}

	c, err := l.newConn(remoteAddr, pubKeyIdRcv, lOpts.privKeyEp, lOpts.pubKeyEpRcv)
	if err != nil {
		slog.Error("cannot create new connection", slog.Any("error", err))
		return nil, err
	}
	return c.New(lOpts.streamId, StreamSndStarting, !lOpts.noLoop, true)
}
