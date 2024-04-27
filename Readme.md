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
* 0-RTT (first request always needs to be equal or larger than its reply -> fill up to MTU)
* No perfect forward secrecy for 1st message if payload is sent in first message
* P2P friendly (id peers by ed25519 public key, for both sides)
* Closing is immediate, to keep connection open, keep-alive every 10s is mandatory

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
INIT_REPLY <- [version 6bit | type 2bit | pubKeyIdShortRcv 32bit | pukKeyIdShortSnd 32bit] pukKeyEpSnd 256bit | nonce 192bit | [payload encrypted] | mac 128bit
(33 bytes until payload)
MSG       <-> [version 6bit | type 2bit | pubKeyIdShortRcv 32bit | pukKeyIdShortSnd 32bit] nonce 192bit | [payload encrypted] | mac 128bit

## Payload Format (transport layer) - min. 9 bytes 

Types:
* STREAM_ID 32bit: the id of the stream
* RCV_WND_SIZE 32bit: max buffer per slot (x 1400 bytes) -> ~5.6TB
* ACK/SACK/FIN Header 8bit (DATA 0bit | FIN 1bit | FIN_ACK 2bit | ACK 3bit | sack_len 4-7bit)
 * ACK_SEQ 32bit, [ACK_FROM 32bit, ACK_TO 32bit]
* (only if DATA bit set) SEQ_NR 32bit - QUIC also has 32bit, should this be increased?
* (only if DATA bit set) DATA - rest

Connection context: keeps track of MIN_RTT, last 5 RTTs, SND_WND_SIZE (cwnd)
Stream context: keeps track of SEQ_NR per stream, RCV_WND_SIZE (rwnd)