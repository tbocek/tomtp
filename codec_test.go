package tomtp

import (
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/netip"
	"testing"
)

var (
	seed1 = [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	seed2 = [32]byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	seed3 = [32]byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	seed4 = [32]byte{4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	seed5 = [32]byte{5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	seed6 = [32]byte{6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	prvIdAlice, _     = ecdh.X25519().NewPrivateKey(seed1[:])
	prvIdBob, _       = ecdh.X25519().NewPrivateKey(seed2[:])
	prvEpAlice, _     = ecdh.X25519().NewPrivateKey(seed3[:])
	prvEpBob, _       = ecdh.X25519().NewPrivateKey(seed4[:])
	prvEpAliceRoll, _ = ecdh.X25519().NewPrivateKey(seed5[:])
	prvEpBobRoll, _   = ecdh.X25519().NewPrivateKey(seed6[:])
)

func TestStreamEncode(t *testing.T) {
	tests := []struct {
		name           string
		setupStream    func() *Stream
		input          []byte
		expectedError  error
		validateOutput func(*testing.T, []byte, error)
	}{
		{
			name: "Stream closed",
			setupStream: func() *Stream {
				stream := &Stream{
					state: StreamEnded,
				}
				return stream
			},
			input:         []byte("test dataToSend"),
			expectedError: ErrStreamClosed,
		},
		{
			name: "Connection closed",
			setupStream: func() *Stream {
				stream := &Stream{
					state: StreamOpen,
					conn: &Connection{
						state: ConnectionEnded,
					},
				}
				return stream
			},
			input:         []byte("test dataToSend"),
			expectedError: ErrStreamClosed,
		},
		{
			name: "Initial sender packet",
			setupStream: func() *Stream {
				conn := &Connection{
					firstPaket:          true,
					sender:              true,
					snCrypto:            0,
					mtu:                 1400,
					pubKeyIdRcv:         prvIdBob.PublicKey(),
					prvKeyEpSnd:         prvEpAlice,
					prvKeyEpSndRollover: prvEpAliceRoll,
					listener: &Listener{
						prvKeyId: prvIdAlice,
					},
					rbRcv: NewReceiveBuffer(1000),
				}
				stream := &Stream{
					state: StreamOpen,
					conn:  conn,
				}
				return stream
			},
			input: []byte("test dataToSend"),
			validateOutput: func(t *testing.T, output []byte, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, output)
			},
		},
		{
			name: "Initial handshake S0",
			setupStream: func() *Stream {
				conn := &Connection{
					firstPaket:          true,
					sender:              true,
					snCrypto:            0,
					mtu:                 1400,
					prvKeyEpSnd:         prvEpAlice,
					prvKeyEpSndRollover: prvEpAliceRoll,
					listener: &Listener{
						prvKeyId: prvIdAlice,
					},
					rbRcv: NewReceiveBuffer(1000),
				}
				return &Stream{
					state: StreamOpen,
					conn:  conn,
				}
			},
			input: nil,
			validateOutput: func(t *testing.T, output []byte, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, output)

				// Verify it's an InitHandshakeS0 message
				_, msgType, err := decodeHeader(output)
				assert.NoError(t, err)
				assert.Equal(t, InitHandshakeS0MsgType, msgType)
			},
		},
		{
			name: "Initial handshake R0",
			setupStream: func() *Stream {
				conn := &Connection{
					firstPaket:          true,
					sender:              false,
					isHandshake:         true,
					snCrypto:            0,
					mtu:                 1400,
					pubKeyIdRcv:         prvIdAlice.PublicKey(),
					prvKeyEpSnd:         prvEpBob,
					prvKeyEpSndRollover: prvEpBobRoll,
					pubKeyEpRcv:         prvEpAlice.PublicKey(),
					listener: &Listener{
						prvKeyId: prvIdBob,
					},
					rbRcv: NewReceiveBuffer(1000),
				}
				return &Stream{
					state: StreamOpen,
					conn:  conn,
				}
			},
			input: []byte("handshake response"),
			validateOutput: func(t *testing.T, output []byte, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, output)

				// Verify it's an InitHandshakeR0 message
				_, msgType, err := decodeHeader(output)
				assert.NoError(t, err)
				assert.Equal(t, InitHandshakeR0MsgType, msgType)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := tt.setupStream()
			output, err := stream.encode(tt.input, nil)

			if tt.expectedError != nil {
				assert.Equal(t, tt.expectedError, err)
				return
			}

			if tt.validateOutput != nil {
				tt.validateOutput(t, output, err)
			}
		})
	}
}

func TestEndToEndCodec(t *testing.T) {
	// Setup listener
	lAlice := &Listener{
		connMap:  make(map[uint64]*Connection),
		prvKeyId: prvIdAlice,
	}

	// Create a test stream
	connAlice := &Connection{
		firstPaket:          true,
		sender:              true,
		snCrypto:            0,
		mtu:                 1400,
		pubKeyIdRcv:         prvIdBob.PublicKey(),
		prvKeyEpSnd:         prvEpAlice,
		prvKeyEpSndRollover: prvEpAliceRoll,
		listener:            lAlice,
		rbRcv:               NewReceiveBuffer(1000),
	}

	streamAlice := &Stream{
		state: StreamOpen,
		conn:  connAlice,
	}

	lBob := &Listener{
		connMap:  make(map[uint64]*Connection),
		prvKeyId: prvIdBob,
	}

	// Test encoding and decoding
	testData := []byte("test message")
	encoded, err := streamAlice.encode(testData, nil)
	require.NoError(t, err)
	require.NotNil(t, encoded)

	a, _ := netip.ParseAddr("127.0.0.1")
	remoteAddr := netip.AddrPortFrom(a, uint16(8080))

	c, m, err := lBob.decode(encoded, remoteAddr)
	require.NoError(t, err)
	s, _, err := c.decode(m.PayloadRaw, 0)
	require.NoError(t, err)
	rb, err := s.ReadBytes()
	require.NoError(t, err)
	assert.Equal(t, testData, rb)
}

func TestEndToEndCodecLargeData(t *testing.T) {
	// Test with various dataToSend sizes
	dataSizes := []int{100, 1000, 2000, 10000}
	for _, size := range dataSizes {
		// Create Alice's connection and stream

		// Setup listeners
		lAlice := &Listener{
			connMap:  make(map[uint64]*Connection),
			prvKeyId: prvIdAlice,
		}
		lBob := &Listener{
			connMap:  make(map[uint64]*Connection),
			prvKeyId: prvIdBob,
		}

		connAlice := &Connection{
			firstPaket:          true,
			sender:              true,
			snCrypto:            0,
			mtu:                 1400,
			pubKeyIdRcv:         prvIdBob.PublicKey(),
			prvKeyEpSnd:         prvEpAlice,
			prvKeyEpSndRollover: prvEpAliceRoll,
			listener:            lAlice,
			rbSnd:               NewSendBuffer(rcvBufferCapacity),
			rbRcv:               NewReceiveBuffer(12000),
		}
		connId := binary.LittleEndian.Uint64(prvIdAlice.PublicKey().Bytes()) ^ binary.LittleEndian.Uint64(prvIdBob.PublicKey().Bytes())
		lAlice.connMap[connId] = connAlice

		streamAlice := &Stream{
			state: StreamOpen,
			conn:  connAlice,
		}

		a, _ := netip.ParseAddr("127.0.0.1")
		remoteAddr := netip.AddrPortFrom(a, uint16(8080))

		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			testData := make([]byte, size)
			for i := 0; i < len(testData); i++ {
				testData[i] = byte(i % 256)
			}

			remainingData := testData
			var decodedData []byte

			encoded, err := streamAlice.encode(remainingData, nil)
			require.NoError(t, err)
			require.NotNil(t, encoded)

			connBob, m, err := lBob.decode(encoded, remoteAddr)
			require.NoError(t, err)
			s, _, err := connBob.decode(m.PayloadRaw, 0)
			require.NoError(t, err)
			rb, err := s.ReadBytes()
			require.NoError(t, err)
			decodedData = append(decodedData, rb...)

			streamBob, _ := connBob.GetOrNewStreamRcv(s.streamId)
			encoded, err = streamBob.encode([]byte{}, nil)
			require.NoError(t, err)
			require.NotNil(t, encoded)

			connAlice, m, err = lAlice.decode(encoded, remoteAddr)
			s, _, err = connAlice.decode(m.PayloadRaw, 0)
			require.NoError(t, err)
			//rb, err = s.ReadBytes()
			//require.NoError(t, err)

			assert.Equal(t, testData, decodedData, "Data mismatch for Size %d", size)
		})
	}
}

func TestFullHandshakeFlow(t *testing.T) {
	// Setup listeners
	lAlice := &Listener{
		connMap:  make(map[uint64]*Connection),
		prvKeyId: prvIdAlice,
	}
	lBob := &Listener{
		connMap:  make(map[uint64]*Connection),
		prvKeyId: prvIdBob,
	}

	// Test InitHandshakeS0 -> InitHandshakeR0 flow
	t.Run("Initial Handshake Flow", func(t *testing.T) {
		// Alice creates initial handshake

		connAlice := &Connection{
			connId:              1,
			firstPaket:          true,
			sender:              true,
			isHandshake:         true,
			snCrypto:            0,
			mtu:                 1400,
			prvKeyEpSnd:         prvEpAlice,
			prvKeyEpSndRollover: prvEpAliceRoll,
			listener:            lAlice,
			rbRcv:               NewReceiveBuffer(1000),
		}
		lAlice.connMap[connAlice.connId] = connAlice

		streamAlice := &Stream{
			state: StreamOpen,
			conn:  connAlice,
		}

		// Alice encodes InitHandshakeS0
		encoded, err := streamAlice.encode(nil, nil)
		require.NoError(t, err)
		require.NotNil(t, encoded)

		// Bob receives and decodes InitHandshakeS0
		a, _ := netip.ParseAddr("127.0.0.1")
		remoteAddr := netip.AddrPortFrom(a, uint16(8080))

		connBob, msgS0, err := lBob.decode(encoded, remoteAddr)
		require.NoError(t, err)
		require.NotNil(t, connBob)
		require.Equal(t, InitHandshakeS0MsgType, msgS0.MsgType)

		// Bob responds with InitHandshakeR0
		streamBob := &Stream{
			state: StreamOpen,
			conn:  connBob,
		}

		// Bob encodes InitHandshakeR0
		testData := []byte("handshake response")
		encodedR0, err := streamBob.encode(testData, nil)
		require.NoError(t, err)
		require.NotNil(t, encodedR0)

		// Alice receives and decodes InitHandshakeR0
		c, m, err := lAlice.decode(encodedR0, remoteAddr)
		require.NoError(t, err)
		s, _, err := c.decode(m.PayloadRaw, 0)
		require.NoError(t, err)
		rb, err := s.ReadBytes()

		require.NoError(t, err)
		require.Equal(t, InitHandshakeR0MsgType, m.MsgType)
		require.Equal(t, testData, rb)
	})

	// Test Data0 message flow
	t.Run("Data0 Message Flow", func(t *testing.T) {
		connId := binary.LittleEndian.Uint64(prvIdAlice.PublicKey().Bytes()) ^ binary.LittleEndian.Uint64(prvIdBob.PublicKey().Bytes())

		// Setup established connection
		connAlice := &Connection{
			firstPaket:          false,
			sender:              true,
			snCrypto:            1,
			mtu:                 1400,
			pubKeyIdRcv:         prvIdBob.PublicKey(),
			prvKeyEpSnd:         prvEpAlice,
			prvKeyEpSndRollover: prvEpAliceRoll,
			pubKeyEpRcv:         prvEpBob.PublicKey(),
			listener:            lAlice,
			rbRcv:               NewReceiveBuffer(1000),
			isRollover:          false,
			sharedSecret:        seed1[:],
		}
		lAlice.connMap[connId] = connAlice

		connBob := &Connection{
			firstPaket:          false,
			sender:              false,
			snCrypto:            1,
			mtu:                 1400,
			pubKeyIdRcv:         prvIdAlice.PublicKey(),
			prvKeyEpSnd:         prvEpBob,
			prvKeyEpSndRollover: prvEpBobRoll,
			pubKeyEpRcv:         prvEpAlice.PublicKey(),
			listener:            lBob,
			rbRcv:               NewReceiveBuffer(1000),
			isRollover:          false,
			sharedSecret:        seed1[:],
		}
		lBob.connMap[connId] = connBob

		streamAlice := &Stream{
			state: StreamOpen,
			conn:  connAlice,
		}

		// Alice sends Data0
		testData := []byte("data0 message")
		encoded, err := streamAlice.encode(testData, nil)
		require.NoError(t, err)
		require.NotNil(t, encoded)

		// Bob receives and decodes Data0
		a, _ := netip.ParseAddr("127.0.0.1")
		remoteAddr := netip.AddrPortFrom(a, uint16(8080))

		c, msg, err := lBob.decode(encoded, remoteAddr)
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, DataMsgType, msg.MsgType)

		s, _, err := c.decode(msg.PayloadRaw, 0)
		require.NoError(t, err)
		rb, err := s.ReadBytes()
		require.NoError(t, err)
		require.Equal(t, testData, rb)
	})
}
