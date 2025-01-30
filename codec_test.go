package tomtp

import (
	"crypto/ecdh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
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
		validateOutput func(*testing.T, []byte, int, error)
	}{
		{
			name: "Stream closed",
			setupStream: func() *Stream {
				stream := &Stream{
					state: StreamEnded,
				}
				return stream
			},
			input:         []byte("test data"),
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
			input:         []byte("test data"),
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
				}
				stream := &Stream{
					state: StreamOpen,
					conn:  conn,
					rbRcv: NewReceiveBuffer(1000),
				}
				return stream
			},
			input: []byte("test data"),
			validateOutput: func(t *testing.T, output []byte, n int, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, output)
				assert.Greater(t, n, 0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := tt.setupStream()
			output, n, err := stream.encode(tt.input)

			if tt.expectedError != nil {
				assert.Equal(t, tt.expectedError, err)
				return
			}

			if tt.validateOutput != nil {
				tt.validateOutput(t, output, n, err)
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
	}

	streamAlice := &Stream{
		state: StreamOpen,
		conn:  connAlice,
		rbRcv: NewReceiveBuffer(1000),
	}

	lBob := &Listener{
		connMap:  make(map[uint64]*Connection),
		prvKeyId: prvIdBob,
	}

	// Test encoding and decoding
	testData := []byte("test message")
	encoded, n, err := streamAlice.encode(testData)
	require.NoError(t, err)
	require.NotNil(t, encoded)
	require.Greater(t, n, 0)

	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8080,
	}

	_, p, err := lBob.decode(encoded, len(encoded), remoteAddr)
	require.NoError(t, err)
	assert.Equal(t, testData, p.Data)
}
