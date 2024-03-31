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

## Assumptions

* Every node on the world is reachable via network in 1.5 sec. Max RTT is 3sec

## Messages Format (encryption layer)

Version: 0
Types:
* INIT
* INIT_REPLY
* MSG
* N/A

(93 bytes until payload)
(37 bytes until getting state)
INIT       -> [| version 6bit | type 2bit | pubKeyIdRcv 32bit | pukKeyIdSnd 256bit |] pukKeyEpSnd 256bit | nonce 192bit | payload encrypted | fill encrypted | auth 128bit
(65 bytes until payload)
(9 bytes until getting state)
INIT_REPLY <- [| version 6bit | type 2bit | pubKeyIdRcv 32bit | pukKeyIdSnd 32bit |] pukKeyEpSnd 256bit | nonce 192bit | payload encrypted | auth 128bit
(33 bytes until payload)
(9 bytes until getting state)
MSG       <-> [| version 6bit | type 2bit | pubKeyIdRcv 32bit | pukKeyIdSnd 32bit |] nonce 192bit | payload encrypted | auth 128bit

## Payload Format (transport layer)

Types:
* First Reply (FIRST_REPLY)
* Ack / Sack, ARQ
* Message
* BBR

FIRST_REPLY <- | type 2bit | sequenceNr 32bit | pukKeyEpSnd 256bit | data |
