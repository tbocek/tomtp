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
	streamA, isNew := connA.GetOrCreate(0)
	assert.True(t, isNew)
	_, err = streamA.Write(a)
	assert.Nil(t, err)
	_, err = connA.listener.Flush(0)
	assert.Nil(t, err)

	// Process and forward the data
	err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Received data
	streamB, isNew, err := listenerB.Listen(0, 0)
	assert.Nil(t, err)
	assert.True(t, isNew)
	b := streamB.Read()

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
	streamA1, _ := connA.GetOrCreate(0)
	_, err = streamA1.Write(a1)
	assert.Nil(t, err)
	_, err = connA.listener.Flush(0)
	assert.Nil(t, err)

	a2 := []byte("hallo2")
	streamA2, _ := connA.GetOrCreate(1)
	_, err = streamA2.Write(a2)
	assert.Nil(t, err)
	//this should not work, as we can only send 1 packet at the start, that we did with "hallo1"
	_, err = connA.listener.Flush(0)
	assert.Nil(t, err)

	// we send two packets
	err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Received data, verification
	streamB1, isNew, err := listenerB.Listen(0, 0)
	assert.True(t, isNew)
	assert.Nil(t, err)
	b1 := streamB1.Read()
	assert.Equal(t, a1, b1)
	_, err = streamB1.Write(nil)
	assert.Nil(t, err)
	_, err = listenerB.Flush(0)
	assert.Nil(t, err)

	err = connPair.recipientToSender(1)
	assert.Nil(t, err)

	_, _, err = connA.listener.Listen(0, 0)
	assert.Nil(t, err)
	streamA2, _ = connA.GetOrCreate(1)
	//a2Test, err = streamA2.Write(a2)
	//assert.Nil(t, err)
	//assert.Equal(t, 0, len(a2Test))
	_, err = connA.listener.Flush(0)
	assert.Nil(t, err)

	err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	streamB2, isNew, err := listenerB.Listen(0, 0)
	assert.True(t, isNew)
	assert.Nil(t, err)
	b2 := streamB2.Read()
	assert.Equal(t, a2, b2)
}

func TestRTO(t *testing.T) {
	connPair := NewConnPair("addr1", "addr2")
	defer connPair.Conn1.Close()
	defer connPair.Conn2.Close()

	connA, listenerB, err := createTwoStreams(connPair.Conn1, connPair.Conn2, testPrvKey1, testPrvKey2)
	assert.Nil(t, err)

	a1 := []byte("hallo1")
	streamA1, _ := connA.GetOrCreate(0)
	_, err = streamA1.Write(a1)
	assert.Nil(t, err)
	_, err = connA.listener.Flush(0)
	assert.Nil(t, err)

	err = connPair.senderToRecipient(-1)

	_, err = connA.listener.Flush(250*1000 + 1)
	assert.Nil(t, err)

	err = connPair.senderToRecipient(1)

	_, isNew, err := listenerB.Listen(0, 0)
	assert.True(t, isNew)
	assert.Nil(t, err)
}

func TestRTOTimes4(t *testing.T) {
	//TODO
}

//Test CWND
