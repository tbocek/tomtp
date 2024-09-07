package tomtp

import (
	"net"
	"time"
)

type NetworkConn interface {
	ReadFromUDP(p []byte) (n int, remoteAddr net.Addr, err error)
	WriteToUDP(p []byte, addr net.Addr) (n int, err error)
	Close() error
	SetReadDeadline(t time.Time) error
	LocalAddr() net.Addr
}

type UDPNetworkConn struct {
	conn *net.UDPConn
}

func NewUDPNetworkConn(conn *net.UDPConn) *UDPNetworkConn {
	udp := UDPNetworkConn{conn: conn}
	return &udp
}

func (c *UDPNetworkConn) ReadFromUDP(p []byte) (int, net.Addr, error) {
	return c.conn.ReadFromUDP(p)
}

func (c *UDPNetworkConn) WriteToUDP(p []byte, addr net.Addr) (int, error) {
	//check conversion?
	return c.conn.WriteToUDP(p, addr.(*net.UDPAddr))
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
