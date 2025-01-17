package tomtp

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"testing"
)

func copyAndCloseStream(stream *Stream) {
	defer stream.Close()
	slog.Debug("copyAndCloseStream: stream is rw, so we copy from read to write, then we close")
	copyAvailable(stream, stream)
}

func printAndCloseStream(stream *Stream) {
	defer stream.Close()
	slog.Debug("printAndCloseStream: stream is rw, so we copy from read to write, then we close")
	copyAvailable(os.Stdout, stream)
}

func TestSendReceived(t *testing.T) {
	go peerOther()

	listener, err := ListenString(":8881", func(stream *Stream) {
		copyAndCloseStream(stream)
	}, WithSeed(testPrivateSeed1))
	if err != nil {
		log.Fatalf("Error in listening: %s", err)
	}
	defer listener.Close()

	for {
		listener.UpdateRcv(TimeNow())
		listener.UpdateSnd(TimeNow())
	}
}

func peerOther() {
	listener, err := ListenString(":8882", func(stream *Stream) {
		printAndCloseStream(stream)
	}, WithSeed(testPrivateSeed2))
	if err != nil {
		log.Fatalf("Error in listening: %s", err)
	}
	defer listener.Close()

	stream, err := listener.DialString("127.0.0.1:8881", hexPublicKey1)
	if err != nil {
		log.Fatalf("Error in accept: %s", err)
	}

	fmt.Fprintf(stream, "gogogo")

	for {
		listener.UpdateRcv(TimeNow())
		listener.UpdateSnd(TimeNow())
	}
}

func copyAvailable(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 4096)
	n, err := src.Read(buf)
	if n > 0 {
		written, werr := dst.Write(buf[:n])
		return int64(written), werr
	}
	return 0, err
}
