package tomtp

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

type NetworkConn interface {
	ReadFromUDPAddrPort(p []byte, nowMicros int64) (n int, remoteAddr netip.AddrPort, err error)
	CancelRead(nowMicros int64) error
	WriteToUDPAddrPort(p []byte, remoteAddr netip.AddrPort, nowMicros int64) (n int, err error)
	Close(nowMicros int64) error
	SetReadDeadline(deadlineMicros int64) error
	LocalAddrString() string
}

type UDPNetworkConn struct {
	conn            *net.UDPConn
	minReadDeadline int64
	mu              sync.Mutex
}

func NewUDPNetworkConn(conn *net.UDPConn) NetworkConn {
	return &UDPNetworkConn{
		conn:            conn,
		minReadDeadline: 0,
		mu:              sync.Mutex{},
	}
}

func (c *UDPNetworkConn) ReadFromUDPAddrPort(p []byte, nowMicros int64) (int, netip.AddrPort, error) {
	n, a, err := c.conn.ReadFromUDPAddrPort(p)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.minReadDeadline = 0
	return n, a, err
}

func (c *UDPNetworkConn) CancelRead(nowMicros int64) error {
	return c.conn.SetReadDeadline(time.Now())
}

func (c *UDPNetworkConn) WriteToUDPAddrPort(p []byte, remoteAddr netip.AddrPort, nowMicros int64) (int, error) {
	return c.conn.WriteToUDPAddrPort(p, remoteAddr)
}

func (c *UDPNetworkConn) Close(nowMicros int64) error {
	return c.conn.Close()
}

func (c *UDPNetworkConn) SetReadDeadline(deadlineMicros int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// This ensures we always use the earliest deadline
	if deadlineMicros == 0 || deadlineMicros < c.minReadDeadline {
		c.minReadDeadline = deadlineMicros
		return c.conn.SetReadDeadline(time.Now().Add(time.Duration(deadlineMicros) * time.Microsecond))
	}

	return nil
}

func (c *UDPNetworkConn) LocalAddrString() string {
	return c.conn.LocalAddr().String()
}
