# Detox specification

Specification version: 0.1.0

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

* `COMMAND_DHT` - data are consumed by DHT, uses zlib compression (see "Data channel compression" section below)
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
* `COMMAND_FORWARD_INTRODUCTION` - is used by rendezvous node in order to ask introduction node to forward introduction to target node ("Discovery and connection to a friend" section below)
* `COMMAND_GET_NODES_REQUEST` - is used to fetch up to 10 random nodes, queried node is aware of (not necessarily connected to, see "Selection of nodes for routing path creation" section below)
* `COMMAND_GET_NODES_RESPONSE` - response for `COMMAND_GET_NODES_REQUEST` (see "Selection of nodes for routing path creation" section below)

#### Data channel compression
While most of data sent through data channel are encrypted and look random, data sent using `COMMAND_DHT` are in plaintext and generally quite homogeneous. They are also quite lengthy, which means that they don't fit into single data channel packet or even two of them.

In order to improve data transfer efficiency, all of the data sent with `COMMAND_DHT` command are encrypted with zlib using dictionary.
Dictionary is composed from last 5 pieces of data sent using `COMMAND_DHT` command concatenated together with most recent at the end. Compression in each direction is independent.

This way common identifiers and commands are compressed very efficiently with low CPU load and much more often commands fit into single data channel packet, which means much lower latency.

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
* address in 32 bytes DHT public key (see keypairs section below)
* `Noise_NK_25519_ChaChaPoly_BLAKE2b` from [Noise Protocol Framework](https://noiseprotocol.org/) is used for encryption/decryption (payload on `CREATE_REQUEST`, `CREATE_RESPONSE` and `EXTEND_REQUEST` is Noise's handshake message)
* [AEZ block cipher](http://web.cs.ucdavis.edu/%7Erogaway/aez/) is used for re-wrapping (keys for wrapping/unwrapping with AEZ are received by encrypting 32 zero bytes with empty additional data using send/receive Noise CipherState used for encryption/decryption, together with 16 bytes MAC it will give identical 48 bytes keys for wrapping and unwrapping on both sides; nonce is 12 zero bytes and before each wrapping/unwrapping it is incremented starting from the last byte and moving to the first one)
* data MUST only be sent between initiator and responder, all other data sent by other nodes on routing path MUST be ignored

Here is the list of commands supported on Router level:

| Command name                             | Numeric value |
|------------------------------------------|---------------|
| COMMAND_ANNOUNCE                         | 0             |
| COMMAND_FIND_INTRODUCTION_NODES_REQUEST  | 1             |
| COMMAND_FIND_INTRODUCTION_NODES_RESPONSE | 2             |
| COMMAND_INITIALIZE_CONNECTION            | 3             |
| COMMAND_INTRODUCTION                     | 4             |
| COMMAND_CONFIRM_CONNECTION               | 5             |
| COMMAND_CONNECTED                        | 6             |
| COMMAND_DATA                             | 7             |
| COMMAND_PING                             | 8             |

* `COMMAND_ANNOUNCE` - is used for announcement node to the network (see "Announcement to the network" section below)
* `COMMAND_FIND_INTRODUCTION_NODES_REQUEST` - is used for requesting introduction nodes from rendezvous node (see "Discovery and connection to a friend" section below)
* `COMMAND_FIND_INTRODUCTION_NODES_RESPONSE` - response for `COMMAND_FIND_INTRODUCTION_NODES_REQUEST` (see "Discovery and connection to a friend" section below)
* `COMMAND_INITIALIZE_CONNECTION` - is used for instructing rendezvous node to initialize connection to target node through introduction node (see "Discovery and connection to a friend" section below)
* `COMMAND_INTRODUCTION` - is used by introduction node to send introduction to target node (see "Discovery and connection to a friend" section below)
* `COMMAND_CONFIRM_CONNECTION` - is used by target node to respond to introduction and establish connection through rendezvous node (see "Discovery and connection to a friend" section below)
* `COMMAND_CONNECTED` - is used by rendezvous node to confirm that connection to target node is established (see "Discovery and connection to a friend" section below)
* `COMMAND_DATA` - is used for data sending and forwarding (see "Sending data to a friend" section below)
* `COMMAND_PING` - is used for ensuring connection is still working (see "Announcement to the network" section below)

#### One-way encryption
In some cases one-way encryption is used when there is a need to send encrypted piece of data, but there is no two-way communication yet (like during connection to a friend).

In this case Noise's `Noise_N_25519_ChaChaPoly_BLAKE2b` is used and the output is as follows:
* 48 bytes Noise handshake message
* ciphertext, same length as plaintext
* 16 bytes MAC

### Selection of nodes for routing path creation
When routing path is created (see "Routing path creation" section below), we need a set of nodes through which to create this routing path.

The first node in routing path MUST be always the random node to which direct connection is already established. The rest of the nodes MUST be those to which direct connections are not yet established.

Node can send `COMMAND_GET_NODES_REQUEST` transport command with empty contents to the other nodes and in response it will receive `COMMAND_GET_NODES_RESPONSE` transport command that contains concatenated list of up to 10 unique random IDs of nodes queried node is aware of (node SHOULD return up to 7 directly connected nodes and the rest will be nodes it is aware of).
When routing path is created, necessary number of nodes is selected from these known nodes.

TODO: This is a very naive approach and must be improved in future iterations of the spec!

### Routing path creation
Routing path creation is regular Router routing path with pair of multiplexers/demultiplexers on both sides.

Nodes for routing path are selected as described in "Selection of nodes for routing path creation" section above.

Multiplexers/demultiplexers are only used for sending and receiving data, other commands MUST fit into single packet with max size of 509 bytes, so that they take at most 1 data channel packet (actual size of payload that fits into single packet is 488 bytes as Routing is encrypted and has its own overhead).

### Announcement to the network
Announcement to the network is done anonymously through introduction nodes.

Node that wants to introduce itself to the network first creates a few routing paths to introduction nodes.

Once connections are established, node generates announcement message, which is a mutable item according to [BEP 44](http://bittorrent.org/beps/bep_0044.html) as follows:
* key is a long-term Ed25519 public key that node wants to announce itself under
* sequence number is Unix timestamp in milliseconds
* value is a concatenated string of IDs of all of the introduction nodes to which routing paths were created

Announcement message is then presented as object `{k, seq, sig, v}` in bencoded form, where keys are:
* `k` - long-term Ed25519 public key
* `seq` - sequence number
* `sig` - Ed25519 signature
* `v` - IDs of introduction nodes

Announcement message is not published to DHT directly, instead node sends `COMMAND_ANNOUNCE` routing command to introduction nodes through previously created routing paths with announcement message as payload.
When node receives `COMMAND_ANNOUNCE` it becomes aware that it is now acting as introduction node for someone and MUST publish to announcement message to DHT directly, also each 30 minutes introduction node MUST re-send announcement message to DHT.

Node that announced itself SHOULD send `COMMAND_PING` routing command to introduction node at least once per 60 seconds to make sure connection is kept alive, otherwise routing path can be destroyed by introduction node and it will stop forwarding introductions (see "Discovery and connection to a friend" section below).

### Discovery and connection to a friend
Discovery and connection to a friend also happens anonymously using rendezvous node selected by the node that wants to connect and introduction node selected by a friend during announcement to the network.

First of all, node creates routing path to rendezvous node.

Once connection is established, `COMMAND_FIND_INTRODUCTION_NODES_REQUEST` routing command is sent to rendezvous node with data that contains long-term public key of a friend.
Rendezvous node uses DHT to find an item using long-term public key as DHT key.

Once search is done rendezvous node responds with `COMMAND_FIND_INTRODUCTION_NODES_RESPONSE` routing command which contains data as follows:
* 1 byte status code (see below)
* 0 or more Ed25519 public keys of introduction nodes for requested long-term public key

Status codes:

| Code name                   | Numeric value |
|-----------------------------|---------------|
| OK                          | 0             |
| ERROR_NO_INTRODUCTION_NODES | 1             |

* `OK` - introduction nodes were found successfully
* `ERROR_NO_INTRODUCTION_NODES` - introduction nodes were not found

Once introduction nodes are found, random introduction node is selected and introduction message is created as follows:
* 64 bytes - Ed25519 signature of Ed25519 public key of introduction node (not part of introduction payload) concatenated with introduction payload using node's long-term keypair
* 240 bytes - introduction payload

Introduction payload is creates as follows:
* 32 bytes - Own long-term public key
* 32 bytes - Ed25519 public key of rendezvous node
* 32 bytes - rendezvous token (one-time randomly generated string)
* 48 bytes - Noise handshake message for end-to-end encryption with a friend (the same `Noise_NK_25519_ChaChaPoly_BLAKE2b` is used as in routing, long-term public key is used as remote public static key)
* 64 bytes - application (to be interpreted by applications on both sides of conversation, if shorter than 64 bytes MUST be padded with zeroes)
* 32 bytes - secret (to be interpreted by remote node, SHOULD be negotiated beforehand)

Once introduction message is created, it is one-way encrypted (see "One-way encryption" section above) with long-term public key of a friend.

After this `COMMAND_INITIALIZE_CONNECTION` routing command is sent to rendezvous node with contents as follows:
* 32 bytes - rendezvous token, the same as in introduction payload
* 32 bytes - introduction node, the same as in introduction payload
* 32 bytes - target node to which to connect, the same as was requested in `COMMAND_FIND_INTRODUCTION_NODES_REQUEST`
* 368 bytes - encrypted introduction message

When node receives `COMMAND_INITIALIZE_CONNECTION` routing command it becomes aware that it is now acting as rendezvous node for someone.
Now rendezvous node MUST connect to specified introduction node and send `COMMAND_FORWARD_INTRODUCTION` transport command with contents as follows:
* 32 bytes - target node to which to connect
* 368 bytes - encrypted introduction message

When introduction node receives `COMMAND_FORWARD_INTRODUCTION` transport command it will send `COMMAND_INTRODUCTION` routing command to target node through routing path established before `COMMAND_ANNOUNCE` with encrypted introduction message as contents.

When target node receives `COMMAND_INTRODUCTION` from one of introduction nodes it will:
* decrypt introduction message
* verify signature with introduction node ID command came from
* check if application is known and supported
* check if secret is valid taking into account ID of the node that wants to communicate

If secret and application are fine and node wants to establish communication, it will creates new routing path to rendezvous node and will sent `COMMAND_CONFIRM_CONNECTION` routing command with contents as follows:
* 64 bytes - Ed25519 signature of rendezvous token using node's long-term keypair
* 32 bytes - rendezvous token
* 48 bytes - Noise handshake message for end-to-end encryption with a friend (acts as responder, long-term public key is used as local private static key)

Once rendezvous node receives `COMMAND_CONFIRM_CONNECTION` command, it will:
* check if rendezvous token is known
* verify that signature is valid using target node ID from `COMMAND_INITIALIZE_CONNECTION`

If rendezvous token is known and signature is valid, rendezvous node will sent `COMMAND_CONFIRM_CONNECTION` routing command back to the node that sent `COMMAND_INITIALIZE_CONNECTION` with contents as follows:
* 64 bytes - Ed25519 signature of rendezvous token using node's long-term keypair
* 32 bytes - rendezvous token
* 48 bytes - Noise handshake message for end-to-end encryption with a friend (acts as responder, long-term public key is used as local private static key)

Once `COMMAND_CONFIRM_CONNECTION` is received, connection to a friend is considered established and any `COMMAND_DATA` routing commands received on routing paths MUST be blindly forwarded by rendezvous node to target node and back.

### Friendship requests
Friendship is not specified as special entity or something, but there is a way to make it work.

Node can create special `secret` (see "Discovery and connection to a friend" section above) that will be commonly used for friendship requests.
This way when `COMMAND_INTRODUCTION` routing command is received with this `secret`, application might interpret it as friendship request instead of rejecting immediately.

In case this `secret` happens to appear in hands of spammers, it can be changed and all requests with old one will be ignored. Moreover, application can have multiple such `secret`s for different purposes, so that it doesn't have to revoke all of them at once.

### Sending data to a friend
In order to make sure data packets always fit into single data channel packet multiplexing/demultiplexing is used with max data length of 65535 bytes and packet size of 472 bytes:
* 512 of data channel packet
* - 3 for data channel packet header
* - 16 for block-level MAC (we encrypt each block with one-way encryption, see "One-way encryption" section above, as it will be sent through rendezvous node, which MUST NOT be able to read contents)
* - 2 for Ronion's segment ID
* - 1 for Ronion's command
* - 2 for Ronion's command data length
* - 16 for Ronion's MAC

This way each encrypted block of data will be encrypted and will occupy exactly 1 data channel packet, so that even rendezvous node will not know what data of which size it forwards.

Data are send to rendezvous node using `COMMAND_DATA` routing command by 2 sides of the conversation and rendezvous node transparently forwards data to the other side just like if 2 friends have direct routing path between them.

Each piece of data has command and payload. Command is 1 byte unsigned integer and payload is what needs to be sent. Command interpretation and payload format depends on application.

In order to send data to a friend, node:
* concatenates command byte and payload
* multiplexes the result into chunks of 472 bytes each
* encrypts each chunk with Noise's ChiperState established using Noise handshake messages exchanged during connection process (see "Discovery and connection to a friend" section above)
* sends each encrypted chunk using `COMMAND_DATA` routing command to rendezvous node

When `COMMAND_DATA` routing command is received, node:
* decrypts contents with Noise's CipherState
* feeds the result into demultiplexer
* when demultiplexer returns data, then first byte is command and the rest is payload

### Acknowledgements
Detox is heavily inspired by [Tor](https://www.torproject.org/) and [Tox](https://tox.chat/).
