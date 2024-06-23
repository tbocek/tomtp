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

* Always encrypted (ed25519/curve25519/chacha20-poly1305) - but no renegotiate of shared key 
* 0-RTT (first request always needs to be equal or larger than its reply -> fill up to MTU)
* No perfect forward secrecy for 1st message if payload is sent in first message (request and reply)
* P2P friendly (id peers by ed25519 public key, for both sides)
* No FIN/FINACK, close due to not receiving 3 x keep-alive, keep-alive every x ms is mandatory
* No SSL/TLS, encryption with AEAD (Authenticated Encryption with Associated Data)
* Less than 3k LoC, currently at 1.8k LoC

```
echo "Source Code LoC"; ls -I "*_test.go" | xargs tokei; echo "Test Code LoC"; ls *_test.go | xargs tokei

Source Code LoC
===============================================================================
 Language            Files        Lines         Code     Comments       Blanks
===============================================================================
 Go                     11         2215         1796          110          309
 Markdown                1           76            0           58           18
===============================================================================
 Total                  12         2291         1796          168          327
===============================================================================
Test Code LoC
===============================================================================
 Language            Files        Lines         Code     Comments       Blanks
===============================================================================
 Go                      5         1191          819          197          175
===============================================================================
 Total                   5         1191          819          197          175
===============================================================================
```

## Assumptions

* Every node on the world is reachable via network in 1.5 sec. Max RTT is 3sec
* Sequence nr is 32bit -> 4b packets in flight with 1400 bytes size for 1.5 sec. Worst case reorder 
is first <-> last. Thus, what is the bandwidth that can handle worst case: ~29 Tbit/sec
2^32 * 1400 * 8 / 1.5 -> 
 * 48bit is 2^48 * 1400 * 8 / 1.5 -> ~1.8 Ebit/sec
 * 64bit is 2^64 * 1400 * 8 / 1.5 -> ~116 Zbit/sec
 * Current fastest speed: 22.9 Pbit/sec (https://newatlas.com/telecommunications/datat-transmission-record-20x-global-internet-traffic/)
 * Question: how realistic is worst-case-reorder? QUIC has only 32bit

## Messages Format (encryption layer)

Current version: 0

Types:
* INIT
* INIT_REPLY
* MSG
* N/A

(93 bytes until payload)
INIT       -> [version 6bit | type 2bit | pubKeyIdShortRcv 32bit | pukKeyIdSnd 256bit] pukKeyEpSnd 256bit | nonce 192bit | [fill len 16bit | fill encrypted | payload encrypted] | mac 128bit
(65 bytes until payload)
INIT_REPLY <- [version 6bit | type 2bit | pubKeyIdShortRcv 32bit | pukKeyIdShortSnd 32bit] pukKeyEpRcv 256bit | nonce 192bit | [payload encrypted] | mac 128bit
(33 bytes until payload)
MSG       <-> [version 6bit | type 2bit | pubKeyIdShortRcv 32bit | pukKeyIdShortSnd 32bit] nonce 192bit | [payload encrypted] | mac 128bit

## Payload Format (transport layer) - min. 9 bytes , max (w/o data). 49 

Types:
* STREAM_ID 32bit: the id of the stream
* RCV_WND_SIZE 32bit: max buffer per slot (x 1400 bytes) -> ~5.6TB
* ACK/SACK 8bit (0bit ACK | payload type 1bit data/sn | 2-4bit SACK length  | 5-7bit NOT USED)
 * 0bit set - ACK
   * ACK_SEQ 32bit, 3bit list length: [ACK_FROM 32bit, ACK_TO 32bit]
 * 1bit set - Data
   * SEQ_NR 32bit - QUIC also has 32bit, should this be increased?
   * DATA - rest (can be empty)

-> to send keep alive set ACK/SACK / Payload / SACK length to 0.
 

Connection context: keeps track of MIN_RTT, last 5 RTTs, SND_WND_SIZE (cwnd)
Stream context: keeps track of SEQ_NR per stream, RCV_WND_SIZE (rwnd)

Connection termination, FIN is not acknowledged, sent best effort, otherwise timeout closes the connection.

There is a heartbeat every 1s, that is a packet with data flag, but empty data if no data present.

## States

### How to open a stream and what could go wrong

```
SND --->    MSG_INIT
(starting)  
            MSG_INIT -----> RCV
            MSG_INIT_ACK <- RCV
                            (open)
SND <---    MSG_INIT_ACK                
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