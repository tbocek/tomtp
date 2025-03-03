package tomtp

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"log/slog"
	"testing"
)

func setupInMemoryPair() (NetworkConn, NetworkConn) {
	connPair := NewConnPair("addr1", "addr2")
	return connPair.Conn1, connPair.Conn2
}

func createTwoStreams(
	nConnA NetworkConn,
	nConnB NetworkConn,
	prvKeyA *ecdh.PrivateKey,
	prvKeyB *ecdh.PrivateKey,
	acceptB func(s *Stream),
) (streamA *Stream, listenerB *Listener, err error) {

	var listenerA *Listener

	acceptA := func(s *Stream) {
		slog.Info("A: accept connection")
	}
	listenAddrA := nConnA.LocalAddrString()
	listenerA, err = ListenString(listenAddrA, acceptA, WithNetworkConn(nConnA), WithPrvKeyId(prvKeyA))
	if err != nil {
		return nil, nil, errors.New("failed to create listener A: " + err.Error())
	}

	listenAddrB := nConnB.LocalAddrString()
	listenerB, err = ListenString(listenAddrB, acceptB, WithNetworkConn(nConnB), WithPrvKeyId(prvKeyB))
	if err != nil {
		//Important: close listener A here as listener B might not close it
		listenerA.Close()
		return nil, nil, errors.New("failed to create listener B: " + err.Error())
	}

	connA, err := listenerA.DialWithCryptoString(nConnB.LocalAddrString(), hexPubKey2)
	if err != nil {
		listenerA.Close() // clean up everything here!
		listenerB.Close()
		return nil, nil, errors.New("failed to dial A from B: " + err.Error())
	}
	if connA == nil {
		listenerA.Close()
		listenerB.Close()
		return nil, nil, errors.New("connection should not be nil")
	}

	streamA, _ = connA.GetOrNewStreamRcv(0)

	return streamA, listenerB, nil
}

func TestEndToEndInMemory(t *testing.T) {
	nConnA, nConnB := setupInMemoryPair()
	defer nConnA.Close()
	defer nConnB.Close()

	var streamB *Stream
	streamA, listenerB, err := createTwoStreams(nConnA, nConnB, testPrvKey1, testPrvKey2, func(s *Stream) { streamB = s })
	assert.Nil(t, err)

	a := []byte("hallo")
	_, err = streamA.Write(a)
	assert.Nil(t, err)
	err = streamA.conn.listener.Update(0)
	assert.Nil(t, err)
	//_, err = relayData(nConnA, nConnB, startMtu)
	//assert.Nil(t, err)
	err = listenerB.Update(0)
	assert.Nil(t, err)
	b, err := streamB.ReadBytes()
	assert.Nil(t, err)
	assert.Equal(t, a, b)
}

func TestSlowStart(t *testing.T) {
	nConnA, nConnB := setupInMemoryPair()
	defer nConnA.Close()
	defer nConnB.Close()

	var streamB *Stream
	streamA, listenerB, err := createTwoStreams(nConnA, nConnB, testPrvKey1, testPrvKey2, func(s *Stream) { streamB = s })
	assert.Nil(t, err)

	msgSize := 500
	msgA := make([]byte, msgSize)

	// Send dataToSend from A to B
	_, err = streamA.Write(msgA)
	assert.Nil(t, err)

	err = streamA.conn.listener.Update(0)
	assert.Nil(t, err)
	//_, err = relayData(nConnA, nConnB, startMtu)
	//assert.Nil(t, err)

	err = listenerB.Update(0)
	assert.Nil(t, err)
	//_, err = relayData(nConnB, nConnA, startMtu)
	//assert.Nil(t, err)

	err = streamA.conn.listener.Update(0)
	assert.Nil(t, err)

	//read stream
	msgB := make([]byte, msgSize)
	_, err = streamB.Read(msgB)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			t.Error(err)
		}
	}
	//Assert in order to make test not crash for stream B
	assert.Equal(t, msgA, msgB)

	fmt.Println("cwnd", streamA.conn.BBR.cwnd, "sthress", streamA.conn.BBR.ssthresh, "streamB-Read", streamB.bytesRead)

	lastRead := streamB.bytesRead

	if streamA.conn.BBR.ssthresh <= lastRead {
		t.Error("Did not happen what supposed to happen")
	}
}
