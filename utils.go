package tomtp

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/unix"
	"log/slog"
	"net"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var CurrentUnixTimeDebug uint64 = 0

func timeMilli() uint64 {
	if CurrentUnixTimeDebug != 0 {
		return CurrentUnixTimeDebug
	}
	return uint64(time.Now().UnixMilli())
}

func timeNow() time.Time {
	if CurrentUnixTimeDebug != 0 {
		return time.UnixMilli(int64(CurrentUnixTimeDebug))
	}
	return time.Now()
}

// based on: https://github.com/quic-go/quic-go/blob/d540f545b0b70217220eb0fbd5278ece436a7a20/sys_conn_df_linux.go#L15
func setDF(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var errDFIPv4, errDFIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errDFIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
		errDFIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
	}); err != nil {
		return err
	}

	switch {
	case errDFIPv4 == nil && errDFIPv6 == nil:
		slog.Info("setting DF for IPv4 and IPv6")
		//TODO: expose this and don't probe for higher MTU when not DF not supported
	case errDFIPv4 == nil && errDFIPv6 != nil:
		slog.Info("setting DF for IPv4 only")
	case errDFIPv4 != nil && errDFIPv6 == nil:
		slog.Info("setting DF for IPv6 only")
	case errDFIPv4 != nil && errDFIPv6 != nil:
		slog.Error("setting DF failed for both IPv4 and IPv6")
	}

	return nil
}

func (s *Stream) debug() slog.Attr {
	localAddr := s.conn.listener.localConn.LocalAddr().String()

	if remoteAddr, ok := s.conn.remoteAddr.(*net.UDPAddr); ok {
		lastColonIndex := strings.LastIndex(localAddr, ":")
		return slog.String("net", localAddr[lastColonIndex+1:]+"=>"+strconv.Itoa(remoteAddr.Port))
	} else {
		return slog.String("net", localAddr+"=>"+s.conn.remoteAddr.String())
	}
}

func debugGoroutineID() slog.Attr {
	buf := make([]byte, 64)
	n := runtime.Stack(buf, false)
	buf = buf[:n]
	idField := bytes.Fields(buf)[1]
	var id int64
	fmt.Sscanf(string(idField), "%d", &id)
	return slog.String("gid", fmt.Sprintf("0x%02x", id))
}
