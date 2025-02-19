package tomtp

import (
	"crypto/ecdh"
	"net/netip"
)

func (l *Listener) DialString(remoteAddrString string) (*Connection, error) {
	remoteAddr, err := netip.ParseAddrPort(remoteAddrString)
	if err != nil {
		return nil, err
	}

	return l.Dial(remoteAddr)
}

func (l *Listener) DialWithCryptoString(remoteAddrString string, pubKeyIdRcvHex string) (*Connection, error) {
	remoteAddr, err := netip.ParseAddrPort(remoteAddrString)
	if err != nil {
		return nil, err
	}

	pubKeyIdRcv, err := decodeHexPubKey(pubKeyIdRcvHex)
	if err != nil {
		return nil, err
	}

	return l.DialWithCrypto(remoteAddr, pubKeyIdRcv)
}

func (l *Listener) DialWithCrypto(remoteAddr netip.AddrPort, pubKeyIdRcv *ecdh.PublicKey) (*Connection, error) {
	prvKeyEp, prvKeyEpRollover, err := generateTwoKeys()
	if err != nil {
		return nil, err
	}

	return l.newConn(remoteAddr, prvKeyEp, prvKeyEpRollover, pubKeyIdRcv, nil, nil, true)
}

func (l *Listener) Dial(remoteAddr netip.AddrPort) (*Connection, error) {
	prvKeyEp, prvKeyEpRollover, err := generateTwoKeys()
	if err != nil {
		return nil, err
	}

	return l.newConnHandshake(remoteAddr, prvKeyEp, prvKeyEpRollover)
}
