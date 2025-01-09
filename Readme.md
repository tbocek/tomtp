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

## Features / Limitations

* Always encrypted (curve25519/chacha20-poly1305) - renegotiate of shared key on sequence number overflow (tdb)
* Support for streams
* 0-RTT (first request always needs to be equal or larger than its reply -> fill up to MTU)
* No perfect forward secrecy for 1st message if payload is sent in first message (request and reply)
* P2P friendly (id peers by ed25519 public key, for both sides)
* FIN/FINACK teardown
*  
* Less than 2k LoC, currently at 1.8k LoC

## Assumptions

* Every node on the world is reachable via network in 1s. Max RTT is 2sec
* Sequence nr is 48bit. This is a lot, but needed to make the double encryption easier.
  * -> packets in flight with 1400 bytes size for 1sec Worst case reorder 
  is first <-> last. Thus, what is the in-flight bandwidth that can handle worst case: 
  48bit is 2^48 * 1400 * 8 -> ~2.7 EB/sec
    * Current fastest speed: 22.9 Pbit/sec - multimode (https://newatlas.com/telecommunications/datat-transmission-record-20x-global-internet-traffic/)
    * Commercial: 402 Tbit/sec - singlemode (https://www.techspot.com/news/103584-blistering-402-tbs-fiber-optic-speeds-achieved-unlocking.html)

However, receiving window buffer is here the bottleneck, as we would need to store the unordered 
packets, and the receiving window size is max 4GB.

## Messages Format (encryption layer)

Current version: 0

Available types:
* INIT_SND (Initiating, without having the connId as state)
* INIT_RCV (Replying, without having the connId as state)
* MSG (everything else)

The available types are not encoded. They are applied as follows:

### Type INIT_SND, min: 103 bytes (79 bytes until payload + min payload 8 bytes + 16 bytes MAC)
- **Header (9 bytes):**
  `[8bit version | pubKeyIdShortRcv 64bit XOR pubKeyIdShortSnd 64bit]`
- **Encrypted Header (6 bytes):**
  `[encrypted sequence number 48bit]`
- **Crypto (64 bytes):**
  `[pubKeyIdSnd 256bit | pubKeyEpSnd 256bit]`
- **Payload:** (fill up to full package to prevent amp attacks)
  `[encrypted: payload]`
- **MAC(16 bytes)**:
  `[HMAC-SHA256 of the entire message]`

### Type INIT_RCV, min: 71 bytes (47 bytes until payload + min payload 8 bytes + 16 bytes MAC)
- **Header (9 bytes):**
  `[8bit version | pubKeyIdShortRcv 64bit XOR pubKeyIdShortSnd 64bit]`
- **Encrypted Header (6 bytes):**
  `[encrypted sequence number 48bit]`
- **Crypto (32 bytes):**
  `[pubKeyEpRcv 256bit]`
- **Payload:** (min 8 bytes)
  `[encrypted: payload]`
- **MAC(16 bytes)**:
  `[HMAC-SHA256 of the entire message]`

### Type MSG, min: 39 bytes (15 bytes until payload + min payload 8 bytes + 16 bytes MAC)
- **Header (9 bytes):**
  `[8bit version | pubKeyIdShortRcv 64bit XOR pubKeyIdShortSnd 64bit]`
- **Encrypted Header (6 bytes):**
  `[encrypted sequence number 48bit]`
- **Payload:** (min 8 bytes)
  `[encrypted: payload]`
- **MAC(16 bytes)**:
  `[HMAC-SHA256 of the entire message]`

The length of the complete INIT_REPLY needs to be same or smaller INIT, thus we need to fill up the INIT message. 
The pubKeyIdShortRcv 64bit XOR pukKeyIdShortSnd 64bit identifies the connection Id (connId) for multi-homing.

### Double Encryption with Encoded Sequence Number

Similar to QUIC, TomTP uses a deterministic way to encrypt the sequence number and payload. However, TomTP uses twice
chacha20poly1305.

The `chainedEncrypt` function handles the double encryption process for messages,
particularly focusing on encoding and encrypting the sequence number (`sn`) for `Msg` type messages.
Here's a detailed breakdown of how it works:

1. **Initialization:**
- The function takes parameters including the sequence number, shared secret, data (for signing and encryption),
  and additional data (for signing, but not encryption). The additional data is crypto related, such a public keys.
  First, the data with data for signature is sealed. Sealing means to encrypt and authenticate the provided data
  using the specified nonce and additional data, returning the resulting ciphertext with a MAC appended. There are
  2 options to seal, with a 12byte
- The returned
  seal needs to be at least 24 bytes

1. **Serial Number Serialization:**
- The sequence number is serialized into a byte slice (`snSer`) using little-endian encoding.

1. **Deterministic Nonce Creation:**
- A deterministic nonce (`nonceDet`) is created by XORing the shared secret with parts of the serialized serial number. This ensures that the same nonce is generated for the same sequence number and shared secret, which is crucial for decryption.

1. **First Encryption (AEAD):**
- An AEAD instance is created using `chacha20poly1305.New(sharedSecret)`.
- The payload data (`data`) is encrypted using this AEAD instance with the deterministic nonce and the header and crypto sections as additional data.
- The result of this encryption is stored in `encData`.

1. **Second Encryption for Sequence Number:**
- For `Msg` type messages (where `sn != 1`), a random nonce (`nonceRand`) is extracted from the beginning of the encrypted data (`encData`).
- Another AEAD instance is created using `chacha20poly1305.NewX(sharedSecret)`.
- The serialized serial number (`snSer`) is encrypted using this second AEAD instance with the random nonce.
- Only the first 8 bytes of the result of this encryption are used and appended to the full message.

1. **Message Construction:**
- The header and crypto sections are concatenated into `fullMessage`.
- If it's a `Msg` type message, the first 8 bytes of the second encryption (`encData2[:8]`) are appended.
- Finally, the result of the first encryption (`encData`) is appended to form the complete encrypted message.

1. **Write Message:**
- The constructed full message is written to the output writer (`wr`).

## Encrypted Payload Format (Transport Layer) - min. 6 Bytes (without data)

To simplify the implementation, the header always maintains a fixed size.

### Types:
- **STREAM_FLAGS (8 bits):**
  - 0 bit: Set Close flag 
  - 1 bit: Set Data + opt. filler
  - 2-5 bit: Set ACK Sn (0-15) - if ack set 1-15, also send RCV Window size
  - 6 bit: Set filler (for initial package, and for ping packages, that are less than 8 bytes, and maybe for probing)
  - 7 bit: Set role: 0-initiator, 1-recipient. To not send yourself packets
- **STREAM_ID (32 bits):**
  Represents the stream ID.
  - Size: 4 bytes.
- **op. ACK sn (max 176 bits):**  
  SN to ACK, 1-3 times (1-3x48bits)
  - RCV_WND_SIZE (32 bits):**  
    Size of receive window size.
- **op. FILL (min 16bit, var):**
  16bit filler length
  FILLER
- **op. DATA (min 48bit, var):**
  Prev stream DATA Sn, 48bit (0 if stream start)
  DATA

### Overhead
- **Total Overhead for Data Packets:**  
  39+6 bytes (for a 1400-byte packet, this results in an overhead of ~3.2%).

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



### LoC

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