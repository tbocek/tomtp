package tomtp

import (
	"net"
	"net/netip"
	"time"
)

type NetworkConn interface {
	ReadFromUDPAddrPort(p []byte) (n int, remoteAddr netip.AddrPort, err error)
	WriteToUDPAddrPort(p []byte, remoteAddr netip.AddrPort) (n int, err error)
	Close() error
	SetReadDeadline(t time.Time) error
	LocalAddr() net.Addr
}

type UDPNetworkConn struct {
	conn *net.UDPConn
}

func NewUDPNetworkConn(conn *net.UDPConn) *UDPNetworkConn {
	return &UDPNetworkConn{conn: conn}
}

func (c *UDPNetworkConn) ReadFromUDPAddrPort(p []byte) (int, netip.AddrPort, error) {
	return c.conn.ReadFromUDPAddrPort(p)
}

func (c *UDPNetworkConn) WriteToUDPAddrPort(p []byte, remoteAddr netip.AddrPort) (int, error) {
	return c.conn.WriteToUDPAddrPort(p, remoteAddr)
}

func (c *UDPNetworkConn) Close() error {
	return c.conn.Close()
}

func (c *UDPNetworkConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *UDPNetworkConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}
