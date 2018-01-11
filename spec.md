# Detox specification

Specification version: 0.0.3

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

Command is 1 byte unsigned integer, maximum data length supported here is 65535 bytes, hence data length header will be 2 bytes.

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
| COMMAND_GET_NODES_REQUEST    | 2             |
| COMMAND_GET_NODES_RESPONSE   | 3             |

* `COMMAND_ROUTING` - data are consumed by Router directly
* `COMMAND_FORWARD_INTRODUCTION` - is used by rendezvous node in order to ask introduction node to forward introduction to target node (see "Announcement to the network" and "Discovery and connection to a friend" sections below)
* `COMMAND_GET_NODES_REQUEST` - is used to fetch up to 10 random nodes, queried node is aware of (not necessarily connected to, see "Selection of nodes for routing path creation" section below)
* `COMMAND_GET_NODES_RESPONSE` - response for `COMMAND_GET_NODES_REQUEST` (see "Selection of nodes for routing path creation" section below)

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
When routing path is created (see "Routing path creation" section below), we need a set of nodes through which to create this routing path.

The first node in routing path MUST be always the random node to which direct connection is already established. The rest of the nodes MUST be those to which direct connections are not yet established.

Node can send `COMMAND_GET_NODES_REQUEST` command with empty contents to the other nodes and in response it will receive `COMMAND_GET_NODES_RESPONSE` command that will contain concatenated list of up to 10 unique random IDs of nodes queried node is aware of (not necessarily connected to directly, probably received from other nodes).
When routing path is created, necessary number of nodes is selected from these known nodes.

TODO: This is a very naive approach and must be improved in future iterations of the spec!

### Routing path creation
Routing path creation is regular Router routing path with pair of multiplexers/demultiplexers on both sides.

Nodes for routing path are selected as described in "Selection of nodes for routing path creation" section above.

Multiplexers/demultiplexers are only used for sending and receiving data, other commands MUST fit into single packet with max size of 509 bytes, so that they take at most 1 data channel packet.

### Announcement to the network
TODO

### Discovery and connection to a friend
TODO

### Sending data to a friend
In order to make sure data packets always fit into single data channel packet multiplexing/demultiplexing is used with max data length of 65535 bytes and packet size of 471 bytes:
* 512 of data channel packet
* - 3 for data channel packet header
* - 16 for block-level MAC (we encrypt each block with `Noise_N_25519_ChaChaPoly_BLAKE2b` from Noise Protocol Framework as it will be sent through rendezvous node, which MUST NOT be able to read contents)
* - 1 for Ronion's version
* - 2 for Ronion's segment ID
* - 1 for Ronion's command
* - 2 for Ronion's command data length
* - 16 for Ronion's MAC

This way each encrypted block of data will be encrypted and will occupy exactly 1 data channel packet, so that even rendezvous node will not know what data of which size it forwards.

TODO: the rest of data sending description

TODO: The rest
