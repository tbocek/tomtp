# TomTP

A UDP-based transport protocol that takes an "opinionated" approach, similar to QUIC but with a focus 
on providing reasonable defaults rather than many options, can offer several compelling advantages 
that make it useful for certain applications.

TomTP is peer-to-peer (P2P) friendly, meaning a P2P-friendly protocol often includes easy integration
for NAT traversal, such as UDP hole punching, which can establish connectivity 
between peers behind NATs without requiring manual firewall configuration.

## Similar Projects

* https://github.com/Tribler/utp4j
* https://github.com/quic-go/quic-go
* https://github.com/skywind3000/kcp (no encryption)
* https://github.com/johnsonjh/gfcp (golang version)
* https://eprints.ost.ch/id/eprint/846/
* https://eprints.ost.ch/id/eprint/879/
* https://eprints.ost.ch/id/eprint/979/

## Features

* Always encrypted (ed25519/curve25519/chacha20-poly1305) - no renegotiate of shared key
* Support for streams
* 0-RTT (first request always needs to be equal or larger than its reply -> fill up to MTU)
* No perfect forward secrecy for 1st message if payload is sent in first message (request and reply)
* P2P friendly (id peers by ed25519 public key, for both sides)
* No FIN/FINACK handshake, just one close flag and close due to not receiving 3 x keep-alive, keep-alive every x ms is mandatory
* No SSL/TLS, encryption with AEAD (Authenticated Encryption with Associated Data)
* Less than 3k LoC, currently at 1.8k LoC

```
echo "Source Code LoC"; ls -I "*_test.go" | xargs tokei; echo "Test Code LoC"; ls *_test.go | xargs tokei

Source Code LoC
===============================================================================
 Language            Files        Lines         Code     Comments       Blanks
===============================================================================
 Go                      7         1326         1034          101          191
 Markdown                1          163            0          129           34
===============================================================================
 Total                   8         1489         1034          230          225
===============================================================================
Test Code LoC
===============================================================================
 Language            Files        Lines         Code     Comments       Blanks
===============================================================================
 Go                      4         1409          977          214          218
===============================================================================
 Total                   4         1409          977          214          218
===============================================================================

```

## Assumptions

* Every node on the world is reachable via network in 1s. Max RTT is 2sec
* Sequence nr is 32bit -> 4b packets in flight with 1400 bytes size for 1sec. Worst case reorder 
is first <-> last. Thus, what is the in-flight bandwidth that can handle worst case: ~48 Tbit/sec
2^32 * 1400 * 8 -> 
 * 48bit is 2^48 * 1400 * 8 -> ~3.2 Ebit/sec
 * 64bit is 2^64 * 1400 * 8 -> ~206 Zbit/sec
 * Current fastest speed: 22.9 Pbit/sec - multimode (https://newatlas.com/telecommunications/datat-transmission-record-20x-global-internet-traffic/)
 * Commercial: 402 Tbit/sec - singlemode (https://www.techspot.com/news/103584-blistering-402-tbs-fiber-optic-speeds-achieved-unlocking.html)

TomTP uses 32bit sequence number.

## Messages Format (encryption layer)

Current version: 0

Types:
* INIT
* INIT_REPLY
* MSG_SND
* MSG_RCV

(97 bytes until payload + 16 bytes mac)
INIT       -> [version 6bit | type 2bit | pubKeyIdShortRcv 64bit XOR pukKeyIdShortSnd 64bit] nonce 192bit | pukKeyIdSnd 256bit | pukKeyEpSnd 256bit | [fill len 16bit | fill encrypted | payload encrypted] | mac 128bit
(65 bytes until payload + 16 bytes mac)
INIT_REPLY <- [version 6bit | type 2bit | pubKeyIdShortRcv 64bit XOR pukKeyIdShortSnd 64bit] nonce 192bit | pukKeyEpRcv 256bit | [payload encrypted] | mac 128bit
(33 bytes until payload + 16 bytes mac)
MSG_SND    -> [version 6bit | type 2bit | pubKeyIdShortRcv 64bit XOR pukKeyIdShortSnd 64bit] nonce 192bit | [payload encrypted] | mac 128bit
(33 bytes until payload + 16 bytes mac)
MSG_RCV    <- [version 6bit | type 2bit | pubKeyIdShortRcv 64bit XOR pukKeyIdShortSnd 64bit] nonce 192bit | [payload encrypted] | mac 128bit

The length of INIT_REPLY needs to be same or smaller INIT, thus we need to fill up the INIT message. 
The pubKeyIdShortRcv 64bit XOR pukKeyIdShortSnd 64bit identifies the connection Id (connId). 
We differentiate MSG_SND and MSG_RCV to e.g., prevent the sender trying to decode its own packet.

QUIC uses a 12 byte nonce, while TomTP uses a 24 bytes nonce that is filled randomly. The implementation of the 12 bytes
nonce which includes the sn increases the complexity a lot, since it will be XORed with the packet nr, but on the
receiver side, the packet number must be estimated. Adding 12 bytes makes it much easier.

## Encrypted Payload Format (transport layer) - len (w/o data). 24 bytes

To make the implementation easier, the header has always the same size. QUIC chose to squeeze the header, but this
increases implementation complexity. A typical short header of QUIC is 13 bytes, while TomTP is 21 bytes. For example,
the ACK is separate, while TomTP needs 12 bytes in the header

Types:
* STREAM_ID 32bit: the id of the stream, stream: 0xffffffff means CONNECTION_CLOSE_FLAG //4 
* STREAM_CLOSE_FLAG: 1bit
* RCV_WND_SIZE 31bit: max buffer per slot (x 1400 bytes, QUIC has 64bit) //8
* RLE_ACK (4 + 8 bytes) //20
* SEQ_NR 32bit //24
* Rest: DATA
 
Total overhead: 73 bytes (for 1400 bytes packet, the overhead is ~5.2%). Squeezing the RLE_ACK, RCV_WND_SIZE and nonce out of the header
would save 28 bytes, reducing the header to 45 bytes (for 1400 bytes packet, the overhead is 3.2%). But this is at 
the cost of higher implementation complexity.

To only send keep alive set ACK/SACK / Payload / SACK length to 0, if after 200ms no packet is scheduled to send.
 

Connection context: keeps track of MIN_RTT, last 5 RTTs, SND_WND_SIZE (cwnd)
Stream context: keeps track of SEQ_NR per stream, RCV_WND_SIZE (rwnd)

Connection termination, FIN is not acknowledged, sent best effort, otherwise timeout closes the connection.

There is a heartbeat every 200ms, that is a packet with data flag, but empty data if no data present.

## States

This is the good path of creating a stream with or without data:

```
SND --->    MSG_INIT_DATA
(starting)  
            MSG_INIT_DATA -----> RCV
            MSG_INIT_ACK_DATA <- RCV
                                 (open)
SND <---    MSG_INIT_ACK_DATA                
(open)                            
```


SND(starting) has a timeout of 3s, if no reply arrives, the stream is closed.
(starting) -> (ended). 

If RCV receives a MSG_INIT, the stream is in starting state, it 
sends a MSG_REP_INIT in any case. After the stream is open
(open)

If SND receives MSG_REP_INIT, then the stream is set to open
(starting) -> (open)

SND can mark the stream as closed right after MSG_INIT, but the flag is send
out with the 2nd packet, after MSG_REP_INIT was received. Not before. If a
timeout happend, no packet is being sent

If only one message should be sent, then the first msg contains the closed flag. 
RCV sends the reply, RCV goes into the state (ended). if SND receives MSG_REP_INIT,
the state is in the state (ended)

### How to send messages and what could go wrong

```
(open)
SND --->    MSG
                       (open)
            MSG -----> RCV
            MSG_ACK <- RCV
SND <---    MSG_ACK                       
```

Every message needs to be acked unless its a MSG packet with no data, only ACK