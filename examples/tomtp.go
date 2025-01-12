package main

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"tomtp"
)

var (
	testPrivateSeed1 = [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	testPrivateSeed2 = [32]byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	testPrivateKey1  = ed25519.NewKeyFromSeed(testPrivateSeed1[:])
	testPrivateKey2  = ed25519.NewKeyFromSeed(testPrivateSeed2[:])
	hexPublicKey1    = fmt.Sprintf("0x%x", testPrivateKey1.Public())
	hexPublicKey2    = fmt.Sprintf("0x%x", testPrivateKey2.Public())
)

func copyAndCloseStream(stream *tomtp.Stream) {
	defer stream.Close()
	slog.Debug("example: stream is rw, so we copy from read to write, then we close")
	io.Copy(stream, stream)
}

func printAndCloseStream(stream *tomtp.Stream) {
	defer stream.Close()
	slog.Debug("example: stream is rw, so we copy from read to write, then we close")
	io.Copy(os.Stdout, stream)
}

func main() {
	go peerOther()

	listener, err := tomtp.ListenString(":8881", func(stream *tomtp.Stream) {
		copyAndCloseStream(stream)
	}, tomtp.WithSeed(testPrivateSeed1))
	if err != nil {
		log.Fatalf("Error in listening: %s", err)
	}
	defer listener.Close()

	for {
		listener.UpdateRcv(tomtp.TimeNow())
		listener.UpdateSnd(tomtp.TimeNow())
	}
}

func peerOther() {
	listener, err := tomtp.ListenString(":8882", func(stream *tomtp.Stream) {
		printAndCloseStream(stream)
	}, tomtp.WithSeed(testPrivateSeed2))
	if err != nil {
		log.Fatalf("Error in listening: %s", err)
	}
	defer listener.Close()

	stream, err := listener.DialString("127.0.0.1:8881", hexPublicKey1)
	if err != nil {
		log.Fatalf("Error in accept: %s", err)
	}

	fmt.Fprintf(stream, "gogogo")

}
