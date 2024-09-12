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
* Less than 3k LoC, currently at 1.8k LoC

```
echo "Source Code LoC"; ls -I "*_test.go" | xargs tokei; echo "Test Code LoC"; ls *_test.go | xargs tokei

Source Code LoC
===============================================================================
 Language            Files        Lines         Code     Comments       Blanks
===============================================================================
 Go                     12         2323         1868          114          341
 Markdown                1          168            0          129           39
===============================================================================
 Total                  13         2491         1868          243          380
===============================================================================
Test Code LoC
===============================================================================
 Language            Files        Lines         Code     Comments       Blanks
===============================================================================
 Go                      5         1352          950          187          215
===============================================================================
 Total                   5         1352          950          187          215
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

Types:
* INIT
* INIT_REPLY
* MSG_SND
* MSG_RCV

(81 bytes until payload + 16 bytes mac)
INIT       -> [version 6bit | type 2bit | pubKeyIdShortRcv 64bit XOR pukKeyIdShortSnd 64bit] | pukKeyIdSnd 256bit | pukKeyEpSnd 256bit | [fill len 16bit | fill encrypted | payload encrypted] | mac 128bit | sn 64bit
(49 bytes until payload + 16 bytes mac)
INIT_REPLY <- [version 6bit | type 2bit | pubKeyIdShortRcv 64bit XOR pukKeyIdShortSnd 64bit] | pukKeyEpRcv 256bit | [payload encrypted] | mac 128bit | sn 64bit
(17 bytes until payload + 16 bytes mac)
MSG_SND    -> [version 6bit | type 2bit | pubKeyIdShortRcv 64bit XOR pukKeyIdShortSnd 64bit] | [payload encrypted] | mac 128bit | sn 64bit
(17 bytes until payload + 16 bytes mac)
MSG_RCV    <- [version 6bit | type 2bit | pubKeyIdShortRcv 64bit XOR pukKeyIdShortSnd 64bit] | [payload encrypted] | mac 128bit | sn 64bit

The length of INIT_REPLY needs to be same or smaller INIT, thus we need to fill up the INIT message. 
The pubKeyIdShortRcv 64bit XOR pukKeyIdShortSnd 64bit identifies the connection Id (connId). 
We differentiate MSG_SND and MSG_RCV to e.g., prevent the sender trying to decode its own packet.

Similar to QUIC, TomTP uses a deterministic way to encrypt the sequence number and payload. However, TomTP uses twice
chacha20poly1305 and overlaying with XOR the mac. Thus, the same algorithm can be used twice

## Encrypted Payload Format (transport layer) - len (w/o data). 20 bytes

To make the implementation easier, the header has always the same size. QUIC chose to squeeze the header, but this
increases implementation complexity. If all the squeezing is applied to TomTP, we could save 35 bytes per header.

Types:
* STREAM_ID 32bit: the id of the stream, stream: 0xffffffff means CONNECTION_CLOSE_FLAG //4 
* STREAM_CLOSE_FLAG: 1bit
* RCV_WND_SIZE 63bit: max buffer per slot (x 1400 bytes, QUIC has 64bit) //12
* ACK (8 bytes) //20
* Rest: DATA
 
Total overhead for data packets: 53 bytes (for 1400 bytes packet, the overhead is ~3.7%). Squeezing the RCV_WND_SIZE and shorten the sn of the header
as in QUIC would save 8+7 bytes, reducing the header to 38 bytes (for 1400 bytes packet, the overhead is 2.7%). But this is at 
the cost of higher implementation complexity.

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