# Detox specification

Specification version: 0.0.2

Author: Nazar Mokrynskyi

License: Detox specification (this document) is hereby placed in the public domain

### Introduction
This document is a textual specification of Detox. The goal of this document is to give enough guidance to permit a complete and correct implementation.

Refer to the design document if you need a high level overview.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be interpreted as described in IETF [RFC 2119](http://www.ietf.org/rfc/rfc2119.txt).

#### Glossary
* Initiator: the node that initiates communication
* Responder: the node with which initiator wants to communicate
* Routing path: a sequence of nodes that form a path through which initiator and responder are connected and can anonymously send encrypted data
* Friend: a node that have established friendship with another node, so that these 2 nodes are friends with each other

#### Multiplexing/demultiplexing
Multiplexing is happening by appending the original data with data length header (depending on maximum supported data length can be a number in either 1 or more bytes in big endian format) and then splitting the result into chunks of specified size.
If there is not enough data to fill the chunk, we append zero length data until the size of the result is bigger or equal to the size of the chunk (basically, appending data length header containing only zeroes).

In order to demultiplex chunks back into original data we read data size from buffer of received chunks and check if we've received enough data already.
If yes - remove data length header and actual data from the buffer, return the data and read next data length header. If not - wait till next chunk.

### Foundation
Detox is based on DHT and anonymous (onion) routing that share the same encrypted data channel.

#### Data channel
Data channel is WebRTC's RTCDataChannel, where data are sent in packets of 512 bytes at a time after at a fixed rate.

As actual data being sent can be either for DHT's operation or for other purposes, also data will almost always be either larger or smaller that the packet size.
In order to deal with these 2 issues each piece of data being sent is prepended with a command and then multiplexed into data channel and demultiplexed back on receiving side.

Command is 1 byte number, maximum data length supported here is 65535 bytes, hence data length header will be 2 bytes.

So each piece of data sent over data channel have at least 3 bytes overhead, if there is no useful data - empty data blocks (essentially just data length headers) are sent.

Data MUST be sent at fixed rate specified by user (in packets per second, which is internally translated into delay in milliseconds) in alternating direction: first packet forward, first packet back, second packet forward, second packet back and so on.

Packet is sent in response after delay that corresponds to packets rate, but not earlier than next packet is received in response.
This way it is possible to have different packets rates on 2 sides and don't exceed packets rate in general without any need for additional packets rate negotiation.

There are 4 commands supported on data channel level:

| Command name    | Numeric value |
|-----------------|---------------|
| COMMAND_DHT     | 0             |
| COMMAND_TAG     | 1             |
| COMMAND_UNTAG   | 2             |

* `COMMAND_DHT` - data are consumed by DHT
* `COMMAND_TAG` - is used to notify the other node that the other node is using this connection for something more than DHT so that connection SHOULD NOT be closed immediately if not used by DHT itself
* `COMMAND_UNTAG` - is used to notify the other node that this connection is not use for anything other than DHT anymore and MAY be closed is not needed for DHT
* Commands with numeric values `3..9` are reserved for future use.
* Commands with numeric values `10...255` are translated into additional commands from range `0..245`

Additional commands (from range `0..245`):
| Command name                 | Numeric value |
|------------------------------|---------------|
| COMMAND_ROUTING              | 0             |
| COMMAND_FORWARD_INTRODUCTION | 1             |

* `COMMAND_ROUTING` - data are consumed by Router directly
* `COMMAND_FORWARD_INTRODUCTION` - is used by rendezvous node in order to ask introduction node to forward introduction to target node (see "Announcement to the network" and "Discovery and connection to a friend" sections below)

#### DHT
DHT is based on [WebTorrent DHT](https://github.com/nazar-pc/webtorrent-dht), which is in turn based on BitTorrent DHT, make yourself familiar with BitTorrent DHT and WebTorrent DHT first as this document will not cover them.

There is a single important change made to WebTorrent DHT: signaling data besides keys `type`, `sdp` and optional `extensions` contains `signature` key.
`signature` key is a Ed25519 signature (64 bytes) string of `sdp` contents using DHT keypair.

This signature is present to ensure that WebRTC connection is established with intended node, even though SDP was transferred via insecure channel such as unencrypted WebSocket or other node in DHT.

DHT queries and responses are sent with `COMMAND_DHT` as described in previous section.

If node acts as DHT bootstrap node it MUST NOT:
* act as introduction node
* act as rendezvous node
* act as intermediate node on routing paths

#### Router
Anonymous router is based on [Ronion](https://github.com/nazar-pc/ronion) framework, make yourself familiar with Ronion first as this document will not cover it.

Following choices were made for this particular implementation of Ronion:
* packet size is 509 bytes (512 of data channel packet - 3 for data channel packet header)
* address in 32 bytes DHT public key (see key pairs section below)
* `Noise_NK_25519_ChaChaPoly_BLAKE2b` from [Noise Protocol Framework](https://noiseprotocol.org/) is used for encryption/decryption (payload on `CREATE_REQUEST`, `CREATE_RESPONSE` and `EXTEND_REQUEST` is Noise's handshake message)
* [AEZ block cipher](http://web.cs.ucdavis.edu/%7Erogaway/aez/) is used for re-wrapping (keys for wrapping/unwrapping with AEZ are received by encrypting 32 zero bytes with empty additional data using send/receive Noise CipherState used for encryption/decryption, together with 16 bytes MAC it will give identical 48 bytes keys for wrapping and unwrapping on both sides; nonce is 12 zero bytes and before each wrapping/unwrapping it is incremented starting from the last byte and moving to the first one)
* data MUST only be sent between initiator and responder, all other data sent by other nodes on routing path MUST be ignored

### Selection of nodes for routing path creation
TODO

### Announcement to the network
TODO

### Discovery and connection to a friend
TODO

### Sending data to a friend

TODO: The rest
