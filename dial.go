package tomtp

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"strings"
)

func (l *Listener) DialString(remoteAddrString string, pubKeyIdRcvHex string) (*Connection, error) {
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

	return l.Dial(remoteAddr, pubKeyIdRcv)
}

func (l *Listener) Dial(remoteAddr net.Addr, pubKeyIdRcv *ecdh.PublicKey) (*Connection, error) {
	prvKeyEp, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	prvKeyEpRollover, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return l.newConn(remoteAddr, pubKeyIdRcv, prvKeyEp, prvKeyEpRollover, nil, nil, true)
}
