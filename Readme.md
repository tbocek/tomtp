# TomTP

A UDP-based transport protocol that takes an "opinionated" approach, similar to QUIC but with a focus 
on providing reasonable defaults rather than many options. The goal is to have lower complexity, 
simplicity, and security, while still being reasonably performant.

TomTP is peer-to-peer (P2P) friendly, meaning a P2P-friendly protocol often includes easy integration
for NAT traversal, such as UDP hole punching, multi-homing, where data packets can come from different 
source addresses. It does not have a TIME_WAIT state that could exhaust ports and it does not open a socket
for each connection, thus allowing many short-lived connections.

## Similar Projects

* https://github.com/Tribler/utp4j
* https://github.com/quic-go/quic-go
* https://github.com/skywind3000/kcp (no encryption)
* https://github.com/johnsonjh/gfcp (golang version)
* https://eprints.ost.ch/id/eprint/846/
* https://eprints.ost.ch/id/eprint/879/
* https://eprints.ost.ch/id/eprint/979/

## Features

* Always encrypted (curve25519/chacha20-poly1305) - renegotiate of shared key on sequence number overflow (tdb)
* Support for streams
* 0-RTT (first request always needs to be equal or larger than its reply -> fill up to MTU)
* No perfect forward secrecy for 1st message if payload is sent in first message (request and reply)
* P2P friendly (id peers by ed25519 public key, for both sides)
* Only FIN/FINACK teardown
* Less than 2k LoC, currently at 1.8k LoC

```
echo "Source Code LoC"; ls -I "*_test.go" | xargs tokei; echo "Test Code LoC"; ls *_test.go | xargs tokei

Source Code LoC
===============================================================================
 Language            Files        Lines         Code     Comments       Blanks
===============================================================================
 Go                     12         2203         1773           89          341
 Markdown                1          177            0          133           44
===============================================================================
 Total                  13         2380         1773          222          385
===============================================================================
Test Code LoC
===============================================================================
 Language            Files        Lines         Code     Comments       Blanks
===============================================================================
 Go                      5         1366          959          195          212
===============================================================================
 Total                   5         1366          959          195          212
===============================================================================



```

## Assumptions

* Every node on the world is reachable via network in 1s. Max RTT is 2sec
* Sequence nr is 64bit -> packets in flight with 1400 bytes size for 1sec. Worst case reorder 
is first <-> last. Thus, what is the in-flight bandwidth that can handle worst case: 
64bit is 2^64 * 1400 * 8 -> ~206 Zbit/sec
 * Current fastest speed: 22.9 Pbit/sec - multimode (https://newatlas.com/telecommunications/datat-transmission-record-20x-global-internet-traffic/)
 * Commercial: 402 Tbit/sec - singlemode (https://www.techspot.com/news/103584-blistering-402-tbs-fiber-optic-speeds-achieved-unlocking.html)

However, receiving window buffer is here the bottleneck, as we would need to store the unordered 
packets, and the receiving window size is min 1400 X 2^63. Thus, sequence number length is not 
the bottleneck.

## Messages Format (encryption layer)

Current version: 0

Available types:
* INIT
* INIT_REPLY
* MSG

### Type INIT, min: 117 bytes (81 bytes until payload + min payload 20 bytes + 16 bytes MAC)
- **Header (9 bytes):**  
  `[2bit type + 6bit version | pubKeyIdShortRcv 64bit XOR pubKeyIdShortSnd 64bit]`
- **Crypto (64 bytes):**  
  `[pubKeyIdSnd 256bit | pubKeyEpSnd 256bit]`
- **Encrypted Header (8 bytes):**  
  `[encrypted sequence number 64bit]`
- **Payload:**  
  `[encrypted: fill len 16bit | fill | payload | MAC 128bit]`

### Type INIT_REPLY, min: 85 bytes (49 bytes until payload + min payload 20 bytes + 16 bytes MAC)
- **Header (9 bytes):**  
  `[2bit type + 6bit version | pubKeyIdShortRcv 64bit XOR pubKeyIdShortSnd 64bit]`
- **Crypto (32 bytes):**  
  `[pubKeyEpRcv 256bit]`
- **Encrypted Header (8 bytes):**  
  `[encrypted sequence number 64bit]`
- **Payload:**  
  `[encrypted: payload | MAC 128bit]`

### Type MSG, min: 53 bytes (17 bytes until payload + min payload 20 bytes + 16 bytes MAC)
- **Header (9 bytes):**  
  `[2bit type + 6bit version | pubKeyIdShortRcv 64bit XOR pubKeyIdShortSnd 64bit]`
- **Encrypted Header (8 bytes):**  
  `[encrypted sequence number 64bit]`
- **Payload:**  
  `[encrypted: payload | MAC 128bit]`

The length of the complete INIT_REPLY needs to be same or smaller INIT, thus we need to fill up the INIT message. 
The pubKeyIdShortRcv 64bit XOR pukKeyIdShortSnd 64bit identifies the connection Id (connId) for multihoming.

Similar to QUIC, TomTP uses a deterministic way to encrypt the sequence number and payload. However, TomTP uses twice
chacha20poly1305.

## Encrypted Payload Format (Transport Layer) - 20 Bytes (without data)

To simplify the implementation, the header always maintains a fixed size. While protocols like QUIC optimize by squeezing the header size, this increases implementation complexity. If all similar optimizations were applied to **TomTP**, it could save 35 bytes per header.

### Types:
- **STREAM_ID (32 bits):**  
  Represents the stream ID.
    - Special case: `0xffffffff` indicates `CONNECTION_CLOSE_FLAG`.
    - Size: 4 bytes.

- **STREAM_CLOSE_FLAG (1 bit):**  
  Signals the closure of a stream.

- **RCV_WND_SIZE (63 bits):**  
  Represents the receive window size.
    - Size: 12 bytes.

- **ACK (64 bits):**  
  Acknowledgment flag.
    - Size: 20 bytes.

- **Rest:**  
  DATA

### Overhead
- **Total Overhead for Data Packets:**  
  53 bytes (for a 1400-byte packet, this results in an overhead of ~3.7%).

- **Potential Optimizations:**  
  Squeezing the `RCV_WND_SIZE` and shortening the sequence number, as done in QUIC, would save 8 + 7 bytes. This would reduce the header to 38 bytes, bringing the overhead down to ~2.7% for a 1400-byte packet. However, this comes with an increase in implementation complexity.


TODO:

To only send keep alive set ACK / Payload length to 0, if after 200ms no packet is scheduled to send.

No delayed Acks, acks are sent immediately

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