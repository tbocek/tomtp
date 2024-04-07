package tomtp

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"syscall"
)

type Connection struct {
	remoteConn  *net.UDPConn       // this is the remote connection we are connected
	remoteAddr  *net.UDPAddr       // the remote address
	streams     map[uint32]*Stream // 2^32 connections to a single peer
	mu          sync.Mutex
	listener    *Listener
	pubKeyIdRcv ed25519.PublicKey
	send        io.Writer
}

func (l *Listener) NewConnectionString(pubKeyIdRcv ed25519.PublicKey, remoteAddrString string) (*Connection, error) {
	remoteAddr, err := net.ResolveUDPAddr("udp", remoteAddrString)
	if err != nil {
		fmt.Println("Error resolving remote address:", err)
		return nil, err
	}
	return l.NewOrGetConnection(pubKeyIdRcv, remoteAddr)
}

func (l *Listener) NewOrGetConnection(pubKeyIdRcv ed25519.PublicKey, remoteAddr *net.UDPAddr) (*Connection, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var arr [8]byte
	copy(arr[:], pubKeyIdRcv)

	if multiStream, ok := l.multiStreams[arr]; ok {
		return multiStream, nil
	}

	if ListenerCount >= maxConnections {
		return nil, errors.New("maximum number of listeners reached")
	}

	remoteConn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return nil, err
	}
	err = setDF(remoteConn)
	if err != nil {
		return nil, err
	}

	l.multiStreams[arr] = &Connection{
		streams:     make(map[uint32]*Stream),
		remoteAddr:  remoteAddr,
		remoteConn:  remoteConn,
		pubKeyIdRcv: pubKeyIdRcv,
		mu:          sync.Mutex{},
		listener:    l,
		send:        remoteConn,
	}
	ListenerCount++
	return l.multiStreams[arr], nil
}

// based on: https://github.com/quic-go/quic-go/blob/d540f545b0b70217220eb0fbd5278ece436a7a20/sys_conn_df_linux.go#L15
func setDF(remoteConn *net.UDPConn) error {
	fd, err := remoteConn.File()
	if err != nil {
		return err
	}

	var errDFIPv4, errDFIPv6 error
	errDFIPv4 = syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DO)
	errDFIPv6 = syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_MTU_DISCOVER, syscall.IPV6_PMTUDISC_DO)

	switch {
	case errDFIPv4 == nil && errDFIPv6 == nil:
		slog.Debug("Setting DF for IPv4 and IPv6.")
	case errDFIPv4 == nil && errDFIPv6 != nil:
		slog.Debug("Setting DF for IPv4.")
	case errDFIPv4 != nil && errDFIPv6 == nil:
		slog.Debug("Setting DF for IPv6.")
	case errDFIPv4 != nil && errDFIPv6 != nil:
		slog.Debug("setting DF failed for both IPv4 and IPv6")
	}

	return nil
}
