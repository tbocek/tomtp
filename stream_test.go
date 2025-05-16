package tomtp

import (
	"crypto/ecdh"
	"errors"
	"github.com/stretchr/testify/assert"
	"net/netip"
	"testing"
)

func createTwoStreams(
	nConnA *PairedConn,
	nConnB *PairedConn,
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
	streamA := connA.Stream(0)
	_, err = streamA.Write(a)
	assert.Nil(t, err)
	err = connA.listener.Flush(0)
	assert.Nil(t, err)

	// Process and forward the data
	err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Received data
	streamB, err := listenerB.Listen(0, 0)
	assert.Nil(t, err)
	assert.True(t, streamB.state == StreamStateOpen)
	b, err := streamB.Read()
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
	streamA1 := connA.Stream(0)
	_, err = streamA1.Write(a1)
	assert.Nil(t, err)
	err = connA.listener.Flush(0)
	assert.Nil(t, err)

	a2 := []byte("hallo2")
	streamA2 := connA.Stream(1)
	_, err = streamA2.Write(a2)
	assert.Nil(t, err)
	//this should not work, as we can only send 1 packet at the start, that we did with "hallo1"
	err = connA.listener.Flush(0)
	assert.Nil(t, err)

	// we send one packet
	err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Received data, verification
	streamB1, err := listenerB.Listen(0, 0)
	assert.Nil(t, err)
	assert.True(t, streamB1.state == StreamStateOpen)
	b1, err := streamB1.Read()
	assert.Nil(t, err)
	assert.Equal(t, a1, b1)
	_, err = streamB1.Write(nil)
	assert.Nil(t, err)
	err = listenerB.Flush(0)
	assert.Nil(t, err)

	err = connPair.recipientToSender(1)
	assert.Nil(t, err)

	_, err = connA.listener.Listen(0, 0)
	assert.Nil(t, err)
	//streamA2 = connA.Stream(1)
	//a2Test, err = streamA2.Write(a2)
	//assert.Nil(t, err)
	//assert.Equal(t, 0, len(a2Test))
	err = connA.listener.Flush(0)
	assert.Nil(t, err)

	err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	streamB2, err := listenerB.Listen(0, 0)
	assert.Nil(t, err)
	assert.True(t, streamB2.state == StreamStateOpen)
	b2, err := streamB2.Read()
	assert.Nil(t, err)
	assert.Equal(t, a2, b2)
}

func TestRTO(t *testing.T) {
	connPair := NewConnPair("addr1", "addr2")
	defer connPair.Conn1.Close()
	defer connPair.Conn2.Close()

	connA, listenerB, err := createTwoStreams(connPair.Conn1, connPair.Conn2, testPrvKey1, testPrvKey2)
	assert.Nil(t, err)

	a1 := []byte("hallo1")
	streamA1 := connA.Stream(0)
	_, err = streamA1.Write(a1)
	assert.Nil(t, err)
	err = connA.listener.Flush(0)
	assert.Nil(t, err)

	err = connPair.senderToRecipient(-1)

	err = connA.listener.Flush(250*1000 + 1)
	assert.Nil(t, err)

	err = connPair.senderToRecipient(1)

	streamB, err := listenerB.Listen(0, 0)
	assert.Nil(t, err)
	assert.True(t, streamB.state == StreamStateOpen)
}

func TestRTOTimes4Success(t *testing.T) {
	connPair := NewConnPair("addr1", "addr2")
	defer connPair.Conn1.Close()
	defer connPair.Conn2.Close()
	connA, listenerB, err := createTwoStreams(connPair.Conn1, connPair.Conn2, testPrvKey1, testPrvKey2)
	assert.Nil(t, err)
	a1 := []byte("hallo1")
	streamA1 := connA.Stream(0)
	_, err = streamA1.Write(a1)
	assert.Nil(t, err)
	err = connA.listener.Flush(0)
	assert.Nil(t, err)
	err = connPair.senderToRecipient(-1)
	err = connA.listener.Flush(200000 + 1)
	assert.Nil(t, err)
	err = connPair.senderToRecipient(-1)
	err = connA.listener.Flush(200000 + 400000 + 2)
	assert.Nil(t, err)
	err = connPair.senderToRecipient(-1)
	err = connA.listener.Flush(200000 + 400000 + 800000 + 3)
	assert.Nil(t, err)
	err = connPair.senderToRecipient(-1)
	err = connA.listener.Flush(200000 + 400000 + 800000 + 1600000 + 4)
	assert.Nil(t, err)
	err = connPair.senderToRecipient(1)
	streamB, err := listenerB.Listen(0, 0)
	assert.Nil(t, err)
	assert.True(t, streamB.state == StreamStateOpen)
}

func TestRTOTimes4Fail(t *testing.T) {
	connPair := NewConnPair("addr1", "addr2")
	defer connPair.Conn1.Close()
	defer connPair.Conn2.Close()

	connA, _, err := createTwoStreams(connPair.Conn1, connPair.Conn2, testPrvKey1, testPrvKey2)
	assert.Nil(t, err)

	a1 := []byte("hallo1")
	streamA1 := connA.Stream(0)
	_, err = streamA1.Write(a1)
	assert.Nil(t, err)
	err = connA.listener.Flush(0)
	assert.Nil(t, err)
	err = connPair.senderToRecipient(-1)

	err = connPair.senderToRecipient(-1)
	err = connA.listener.Flush(200000 + 1)
	assert.Nil(t, err)
	err = connPair.senderToRecipient(-1)
	err = connA.listener.Flush(200000 + 400000 + 2)
	assert.Nil(t, err)
	err = connPair.senderToRecipient(-1)
	err = connA.listener.Flush(200000 + 400000 + 800000 + 3)
	assert.Nil(t, err)
	err = connPair.senderToRecipient(-1)
	err = connA.listener.Flush(200000 + 400000 + 800000 + 1600000 + 4)
	assert.Nil(t, err)
	err = connPair.senderToRecipient(-1)
	err = connA.listener.Flush(200000 + 400000 + 800000 + 1600000 + 3200000 + 5)
	assert.Nil(t, err)

	err = connA.listener.Flush(0)
	assert.NotNil(t, err)
}

func TestCloseAWithInit(t *testing.T) {
	connPair := NewConnPair("addr1", "addr2")
	defer connPair.Conn1.Close()
	defer connPair.Conn2.Close()
	connA, listenerB, err := createTwoStreams(connPair.Conn1, connPair.Conn2, testPrvKey1, testPrvKey2)
	assert.Nil(t, err)
	streamA := connA.Stream(0)
	a1 := []byte("hallo1")
	_, err = streamA.Write(a1)
	assert.Nil(t, err)
	connA.Close()
	assert.True(t, streamA.state == StreamStateCloseRequest)

	err = connA.listener.Flush(0)
	assert.Nil(t, err)

	// Simulate packet transfer (data packet with FIN flag)
	err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Listener B receives data
	streamB, err := listenerB.Listen(0, 0)
	assert.Nil(t, err)

	// Verify data received correctly
	buffer, err := streamB.Read()
	assert.Nil(t, err)

	assert.True(t, streamB.state == StreamStateCloseReceived)

	assert.Equal(t, a1, buffer)

	err = streamB.conn.listener.Flush(0)

	// B sends ACK back to A
	err = connPair.recipientToSender(1)
	assert.Nil(t, err)

	streamA, err = streamA.conn.listener.Listen(0, 0)
	assert.Nil(t, err)

	buffer, err = streamA.Read()

	assert.True(t, streamA.state == StreamStateClosed)

}

func TestCloseBWithInit(t *testing.T) {
	connPair := NewConnPair("addr1", "addr2")
	defer connPair.Conn1.Close()
	defer connPair.Conn2.Close()
	connA, listenerB, err := createTwoStreams(connPair.Conn1, connPair.Conn2, testPrvKey1, testPrvKey2)
	assert.Nil(t, err)
	streamA := connA.Stream(0)
	a1 := []byte("hallo1")
	_, err = streamA.Write(a1)
	assert.Nil(t, err)
	assert.True(t, streamA.state == StreamStateOpen)

	err = connA.listener.Flush(0)
	assert.Nil(t, err)

	// Simulate packet transfer (data packet with FIN flag)
	err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Listener B receives data
	streamB, err := listenerB.Listen(0, 0)
	assert.Nil(t, err)
	streamB.conn.Close()
	assert.True(t, streamB.state == StreamStateCloseRequest)

	// Verify data received correctly
	buffer, err := streamB.Read()
	assert.Nil(t, err)

	assert.True(t, streamB.state == StreamStateCloseRequest)

	assert.Equal(t, a1, buffer)

	err = streamB.conn.listener.Flush(0)

	// B sends ACK back to A
	err = connPair.recipientToSender(1)
	assert.Nil(t, err)

	streamA, err = streamA.conn.listener.Listen(0, 0)
	assert.Nil(t, err)

	buffer, err = streamA.Read()

	assert.True(t, streamA.state == StreamStateCloseReceived)
}

func TestGarbage1(t *testing.T) {
	connPair := NewConnPair("addr1", "addr2")
	defer connPair.Conn1.Close()
	defer connPair.Conn2.Close()
	connA, listenerB, err := createTwoStreams(connPair.Conn1, connPair.Conn2, testPrvKey1, testPrvKey2)
	assert.Nil(t, err)
	streamA := connA.Stream(0)
	a1 := []byte("hallo1")
	_, err = streamA.Write(a1)
	assert.Nil(t, err)
	assert.True(t, streamA.state == StreamStateOpen)

	err = connA.listener.Flush(0)
	assert.Nil(t, err)

	// Simulate packet transfer (data packet with FIN flag)
	data := make([]byte, 1400)
	err = connPair.senderRawToRecipient("tmp", data)
	assert.Nil(t, err)

	// Listener B receives data
	_, err = listenerB.Listen(0, 0)
	assert.ErrorContains(t, err, "failed to decode InitHandshakeS0")
}

func TestGarbage2(t *testing.T) {
	connPair := NewConnPair("addr1", "addr2")
	defer connPair.Conn1.Close()
	defer connPair.Conn2.Close()
	connA, listenerB, err := createTwoStreams(connPair.Conn1, connPair.Conn2, testPrvKey1, testPrvKey2)
	assert.Nil(t, err)
	streamA := connA.Stream(0)
	a1 := []byte("hallo1")
	_, err = streamA.Write(a1)
	assert.Nil(t, err)
	assert.True(t, streamA.state == StreamStateOpen)

	err = connA.listener.Flush(0)
	assert.Nil(t, err)

	// Simulate packet transfer (data packet with FIN flag)
	err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Listener B receives data
	streamB, err := listenerB.Listen(0, 0)
	assert.Nil(t, err)

	_, err = streamB.Write([]byte("hallo"))
	assert.Nil(t, err)
	err = streamB.conn.listener.Flush(0)

	// Simulate packet transfer (data packet with FIN flag)
	data := make([]byte, 1400)
	err = connPair.recipientRawToSender("tmp", data)
	assert.Nil(t, err)

	streamA, err = streamA.conn.listener.Listen(0, 0)
	assert.ErrorContains(t, err, "failed to decode InitHandshakeS0")
}

func TestBBR(t *testing.T) {
	connPair := NewConnPair("addr1", "addr2")
	defer connPair.Conn1.Close()
	defer connPair.Conn2.Close()
	connA, listenerB, err := createTwoStreams(connPair.Conn1, connPair.Conn2, testPrvKey1, testPrvKey2)
	assert.Nil(t, err)

	//write 64k
	streamA := connA.Stream(0)
	dataA := make([]byte, initBufferCapacity+1)
	dataARemaining, err := streamA.Write(dataA)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(dataARemaining))
	assert.Equal(t, 65535, streamA.conn.rbSnd.totalSize)
	streamA.conn.listener.Flush(0)

	//send data
	assert.Equal(t, 1, connPair.nrOutgoingPacketsSender())
	err = connPair.senderToRecipientAll()
	assert.Nil(t, err)
	assert.Equal(t, 1, connPair.nrIncomingPacketsRecipient())

	//send 64 back
	streamB, err := listenerB.Listen(0, 0)
	assert.Nil(t, err)
	assert.Equal(t, uint64(65535), streamB.conn.rcvWndSize)
	dataB1 := make([]byte, initBufferCapacity+1)
	dataB1Remaining, err := streamB.Write(dataB1)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(dataB1Remaining))
	streamB.conn.listener.Flush(0)

	//send data
	assert.Equal(t, 1, connPair.nrOutgoingPacketsReceiver())
	err = connPair.recipientToSenderAll()
	assert.Nil(t, err)
	assert.Equal(t, 1, connPair.nrIncomingPacketsSender())
	streamA, err = connA.listener.Listen(0, 0)
	assert.Nil(t, err)
	assert.Equal(t, uint64(64285), streamA.conn.rcvWndSize)

	//Handshake done, send dataaaaaaaaa
	streamA.conn.listener.Flush(0)
	assert.Equal(t, 10, connPair.nrOutgoingPacketsSender())
}

func TestBBR2(t *testing.T) {
	connPair := NewConnPair("addr1", "addr2")
	defer connPair.Conn1.Close()
	defer connPair.Conn2.Close()
	connA, listenerB, err := createTwoStreams(connPair.Conn1, connPair.Conn2, testPrvKey1, testPrvKey2)
	assert.Nil(t, err)

	//write 64k
	streamA := connA.Stream(0)
	dataA := make([]byte, initBufferCapacity+1)
	dataARemaining, err := streamA.Write(dataA)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(dataARemaining))
	assert.Equal(t, 65535, streamA.conn.rbSnd.totalSize)
	streamA.conn.listener.Flush(0)
	err = connPair.senderToRecipientAll()
	assert.Nil(t, err)

	streamB, err := listenerB.Listen(0, 0)
	assert.Nil(t, err)
	streamB.conn.listener.Flush(0)
	err = connPair.recipientToSenderAll()
	assert.Nil(t, err)

	bandwidth := uint64(125000) // 1 Mbps
	latency := uint64(20000)    // 20ms one-way latency
	n := calculateTxTime(1400, bandwidth, latency)

	streamA, err = connA.listener.Listen(0, n)
	assert.Nil(t, err)
	streamA.conn.listener.Flush(0)
	err = connPair.senderToRecipientAll()
	assert.Nil(t, err)

	streamB, err = listenerB.Listen(0, 0)
	assert.Nil(t, err)
	streamB.conn.listener.Flush(0)
	err = connPair.recipientToSenderAll()
	assert.Nil(t, err)

	n += calculateTxTime(1400, bandwidth, latency)

	streamA, err = connA.listener.Listen(0, n)
	assert.Nil(t, err)
	streamA.conn.listener.Flush(0)
	err = connPair.senderToRecipientAll()
	assert.Nil(t, err)

}

func calculateTxTime(bytes uint64, bandwidthBytesPerSec uint64, latencyMicros uint64) uint64 {
	transmissionTime := (bytes * 1000000) / bandwidthBytesPerSec
	return transmissionTime + latencyMicros
}
