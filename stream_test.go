package tomtp

import (
	"crypto/ecdh"
	"errors"
	"github.com/stretchr/testify/assert"
	"net/netip"
	"testing"
)

func createTwoStreams(
	nConnA NetworkConn,
	nConnB NetworkConn,
	prvKeyA *ecdh.PrivateKey,
	prvKeyB *ecdh.PrivateKey,
) (connA *Connection, listenerB *Listener, err error) {

	listenerA, err := Listen(nil, WithNetworkConn(nConnA), WithPrvKeyId(prvKeyA))
	if err != nil {
		return nil, nil, errors.New("failed to create listener A: " + err.Error())
	}

	listenerB, err = Listen(nil, WithNetworkConn(nConnB), WithPrvKeyId(prvKeyB))
	if err != nil {
		//Important: close listener A here as listener B might not close it
		listenerA.Close()
		return nil, nil, errors.New("failed to create listener B: " + err.Error())
	}

	pubKeyIdRcv, err := decodeHexPubKey(hexPubKey2)
	if err != nil {
		return nil, nil, err
	}
	connA, err = listenerA.DialWithCrypto(netip.AddrPort{}, pubKeyIdRcv)
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

	return connA, listenerB, nil
}

func TestOneStream(t *testing.T) {
	connPair := NewConnPair("addr1", "addr2")
	defer connPair.Conn1.Close()
	defer connPair.Conn2.Close()

	connA, listenerB, err := createTwoStreams(connPair.Conn1, connPair.Conn2, testPrvKey1, testPrvKey2)
	assert.Nil(t, err)

	// Send data from A to B
	a := []byte("hallo")
	streamA, isNew := connA.GetOrNewStreamRcv(0)
	assert.True(t, isNew)
	_, _, err = streamA.ReadWrite(a, 0)
	assert.Nil(t, err)

	// Process and forward the data
	err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Received data
	streamB, isNew, err := listenerB.UpdateRcv(true, 0)
	assert.Nil(t, err)
	assert.True(t, isNew)
	b, _, err := streamB.ReadWrite(nil, 0)
	assert.Nil(t, err)

	//Verification
	assert.Equal(t, a, b)
}

func TestTwoStream(t *testing.T) {
	connPair := NewConnPair("addr1", "addr2")
	defer connPair.Conn1.Close()
	defer connPair.Conn2.Close()

	connA, listenerB, err := createTwoStreams(connPair.Conn1, connPair.Conn2, testPrvKey1, testPrvKey2)
	assert.Nil(t, err)

	// Send data from A to B
	a1 := []byte("hallo1")
	streamA1, _ := connA.GetOrNewStreamRcv(0)
	_, _, err = streamA1.ReadWrite(a1, 0)
	assert.Nil(t, err)

	a2 := []byte("hallo2")
	streamA2, _ := connA.GetOrNewStreamRcv(1)
	_, _, err = streamA2.ReadWrite(a2, 0)
	assert.Nil(t, err)

	// we send two packets
	err = connPair.senderToRecipient(2)
	assert.Nil(t, err)

	// Received data, verification
	streamB1, isNew, err := listenerB.UpdateRcv(true, 0)
	assert.True(t, isNew)
	assert.Nil(t, err)
	b1, _, err := streamB1.ReadWrite(nil, 0)
	assert.Nil(t, err)
	assert.Equal(t, a1, b1)

	streamB2, isNew, err := listenerB.UpdateRcv(true, 0)
	assert.True(t, isNew)
	assert.Nil(t, err)
	b2, _, err := streamB2.ReadWrite(nil, 0)
	assert.Nil(t, err)
	assert.Equal(t, a2, b2)
}
