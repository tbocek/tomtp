package tomtp

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

type NetworkConn interface {
	ReadFromUDPAddrPort(p []byte) (n int, remoteAddr netip.AddrPort, err error)
	CancelRead() error
	WriteToUDPAddrPort(p []byte, remoteAddr netip.AddrPort) (n int, err error)
	Close() error
	SetReadDeadline(t time.Time) error
	LocalAddr() net.Addr
}

type UDPNetworkConn struct {
	conn            *net.UDPConn
	minReadDeadline time.Time
	mu              sync.Mutex
}

func NewUDPNetworkConn(conn *net.UDPConn) *UDPNetworkConn {
	return &UDPNetworkConn{
		conn:            conn,
		minReadDeadline: time.Time{},
		mu:              sync.Mutex{},
	}
}

func (c *UDPNetworkConn) ReadFromUDPAddrPort(p []byte) (int, netip.AddrPort, error) {
	n, a, err := c.conn.ReadFromUDPAddrPort(p)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.minReadDeadline = time.Time{}
	return n, a, err
}

func (c *UDPNetworkConn) CancelRead() error {
	return c.conn.SetReadDeadline(time.Now())
}

func (c *UDPNetworkConn) WriteToUDPAddrPort(p []byte, remoteAddr netip.AddrPort) (int, error) {
	return c.conn.WriteToUDPAddrPort(p, remoteAddr)
}

func (c *UDPNetworkConn) Close() error {
	return c.conn.Close()
}

func (c *UDPNetworkConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.minReadDeadline.IsZero() || c.minReadDeadline.After(t) {
		c.minReadDeadline = t
		return c.conn.SetReadDeadline(t)
	}
	return nil
}

func (c *UDPNetworkConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}
