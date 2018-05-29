# Detox specification

Specification version: 0.4.1

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
* Peer: the node that has direct connection with local node

#### Multiplexing/demultiplexing
Multiplexing is happening by appending the original data with data length header (depending on maximum supported data length can be a number in either 1 or more bytes in big endian format) and then splitting the result into chunks of specified size.
If there is not enough data to fill the chunk, we append zero length data until the size of the result is bigger or equal to the size of the chunk (basically, appending data length header containing only zeroes).

In order to demultiplex chunks back into original data we read data size from buffer of received chunks and check if we've received enough data already.
If yes - remove data length header and actual data from the buffer, return the data and read next data length header. If not - wait till next chunk.

### Data channel
Data channel in Detox network is WebRTC's RTCDataChannel, where data are sent in packets of 512 bytes at a time after at a fixed rate configured during startup.

Each piece of data being sent is prepended with a command and then multiplexed into data channel and demultiplexed back on receiving side.

Command is 1 byte unsigned integer from range `0..255`. This range is split into few sub-ranges for different purposes.

One way to split commands is by compression:
* compressed commands are from range `0..19`
* uncompressed commands are from range `20..255`

Maximum data length for uncompressed commands is 65534 bytes (one byte is occupied by command), hence data length header for multiplexing/demultiplexing will be 2 bytes.
Data for compressed commands are prepended by one byte containing `0` if data were not compressed and `1` if data were compressed. This is because sometimes compressed data can be longer than uncompressed. Because of this one byte, maximum data length for uncompressed commands is 65533 bytes.
Compression process is described in section "Data channel compression" below.

So each piece of data sent over data channel have at least 3 bytes overhead (4 bytes in case of compressed commands), if there is no useful data - empty data blocks (essentially just data length headers) are sent.

Another way to split commands is by their purpose:
* commands from range `0..9` are DHT commands `DHT_COMMAND_*`
* commands from range `10..19` are translated into compressed core commands `COMPRESSED_CORE_COMMAND_*` from range `0..9`
* command `20` is routing command and is consumed by Router directly
* commands from range `21..255` are translated into uncompressed core commands `UNCOMPRESSED_CORE_COMMAND_*` from range `0..234`

These types of commands will be described in detail in corresponding sections below.

Data MUST be sent at fixed rate specified by user (in packets per second, which is internally translated into delay in milliseconds) in alternating direction: first packet forward, first packet back, second packet forward, second packet back and so on.

Packet is sent in response after delay that corresponds to packets rate, but not earlier than next packet is received in response.
This way it is possible to have different packets rates on 2 sides and don't exceed packets rate in general without any need for additional packets rate negotiation.
If strict alternating order of packets is not honored, it is considered to be protocol violation and connection MUST be dropped immediately.

#### Data channel compression
While most of data sent through data channel are encrypted and look random, DHT commands and compressed core commands will contain data that can be greatly compressed.
They are also quite lengthy, which means that they often don't fit into single data channel packet or even two of them.

In order to improve data transfer efficiency, data for these command are compressed with zlib using dictionary.
Dictionary is composed from last 5 pieces of compressed data sent concatenated together with most recent at the end. Compression in each direction is independent.

This way common identifiers and commands are compressed very efficiently with low CPU load and much more often commands fit into single data channel packet, which means much lower latency.

In case when compression results in data length that is larger than max allowed data size for compressed data, uncompressed data is sent instead.

### Core commands
There are some commands that do not belong to DHT or routing tasks directly, they are called core commands here and can be compressed and uncompressed.

Following compressed commands are available:

| Command name                    | Numeric value |
|---------------------------------|---------------|
| COMPRESSED_CORE_COMMAND_SIGNAL  | 0             |

`COMPRESSED_CORE_COMMAND_SIGNAL` is used for transport layer when there is a need to connect to peer's peer and contains following data:
* 32 bytes - source ID, own DHT public key
* 32 bytes - target ID, DHT public key of peer's peer
* 1 byte - 0 or SDP answer or 1 for SDP offer
* X bytes - SDP itself from WebRTC (no Trickle ICE)
* 64 bytes - ed25519 signature of SDP that corresponds to own DHT public key

When peer receives `COMPRESSED_CORE_COMMAND_SIGNAL` it will first check command data for correctness.
If correct, target ID is compared to own DHT public key and if matches, sends `COMPRESSED_CORE_COMMAND_SIGNAL` command back with own SDP answer details.
If target ID doesn't match to own DHT public key, but matches one of peer's DHT public key, command is forwarded there.

This way peer can facilitate connection between 2 of its peers, it is actively used during lookup process in DHT.

Following uncompressed commands are available:

| Command name                                   | Numeric value |
|------------------------------------------------|---------------|
| UNCOMPRESSED_CORE_COMMAND_FORWARD_INTRODUCTION | 0             |
| UNCOMPRESSED_CORE_COMMAND_GET_NODES_REQUEST    | 1             |
| UNCOMPRESSED_CORE_COMMAND_GET_NODES_RESPONSE   | 2             |
| UNCOMPRESSED_CORE_COMMAND_BOOTSTRAP_NODE       | 3             |

Uncompressed core commands will be described in other sections below, since they are a part of more complex procedures.

### DHT
DHT is based on [ES-DHT](https://github.com/nazar-pc/es-dht) framework, make yourself familiar with ES-DHT first as this document will not cover it.

DHT implementation in Detox makes following choices on top of ES-DHT framework:
* ID space is 256 bits
* uses ed25519 public key as node ID in DHT
* uses ed25519 signatures for mutable values stored in DHT and Blake2b truncated to 256 bits for immutable values
* bootstrap nodes additionally run HTTP server alongside regular DHT operations, so that other nodes can connect to them directly on startup

Here is the list of DHT commands:

| Command name          | Numeric value |
|-----------------------|---------------|
| DHT_COMMAND_RESPONSE  | 0             |
| DHT_COMMAND_GET_STATE | 1             |
| DHT_COMMAND_GET_PROOF | 2             |
| DHT_COMMAND_GET_VALUE | 3             |
| DHT_COMMAND_PUT_VALUE | 4             |

* `DHT_COMMAND_RESPONSE` - generic command sent in response to `DHT_COMMAND_GET_STATE`, `DHT_COMMAND_GET_PROOF` and `DHT_COMMAND_GET_VALUE` commands
* `DHT_COMMAND_GET_STATE` - is used to get latest state of a peer
* `DHT_COMMAND_GET_PROOF` - is used to get a proof that certain peer's peer is in specific state version
* `DHT_COMMAND_GET_VALUE` - is used to get mutable or immutable value
* `DHT_COMMAND_PUT_VALUE` - is used to put mutable or immutable value

Each command's payload has following structure:
* 2 bytes transaction ID
* the rest is command data

Response to commands that expect such a response will need to include the same transaction ID as during request.

#### Get state
In order to get state of a peer (see ES-DHT for details on what state is and why is it needed), `DHT_COMMAND_GET_STATE` command is sent to a peer with following data:
* 0 bytes or 32 bytes - either no data (to get latest state) or state version to get specific state

Response to `DHT_COMMAND_GET_STATE` command contains following data:
* 32 bytes - state version
* 1 byte - unsigned integer, proof height (number of proof blocks)
* 33 bytes * proof_height - proof itself, proofs that peer's ID is in this state version
* 32 bytes * number of peers - IDs of peer's peers that correspond to state version

Upon receiving response, node MUST check response for correctness.

#### Get proof
During lookup process it might be necessary to get a proof that peer's peer corresponds to state version (proof will also contain peer's peer state version).
Proof can be requested using `DHT_COMMAND_GET_PROOF` command with following data:
* 32 bytes - state version for which to get proof
* 32 bytes - peer's peer ID for which to get proof

Response to `DHT_COMMAND_GET_PROOF` command contains following data:
* 33 bytes * X - proof of height X

Upon receiving response, node MUST check response for correctness.

#### Get value
Whenever node wants to get value from DHT, `DHT_COMMAND_GET_VALUE` command is sent with data:
* 32 bytes - key of the value

Response to `DHT_COMMAND_GET_VALUE` command contains following data:
* 0 bytes or X bytes - no data in case value with specified key is unknown or value data structure (see "Put value" section below)

Upon receiving response, node MUST check response for correctness.

#### Put value
There 2 types of values in DHT: mutable and immutable.

Immutable values are easy: key of the value is Blake2b hash of the value truncated to 256 bits.

Mutable values are more complex: key for mutable value is ed25519 public key and value itself is represented by following data structure:
* 4 bytes - unsigned integer in big endian format, value version (allows value updating over time, higher version number overrides lower)
* X bytes - value itself
* 64 bytes - ed25519 signature for version concatenated with value that corresponds to value's key

In order to put value into DHT node through lookup searches for nodes closest to value's key and sends `DHT_COMMAND_PUT_VALUE` to each of nodes with following data:
* 32 bytes - value's key
* X bytes - value's data structure in case of mutable value or simply value itself in case of immutable value.

Upon receiving `DHT_COMMAND_PUT_VALUE` request, node MUST check it for correctness.

Max value length is 1024 bytes.

### Bootstrap node
Bootstrap node is a node that besides regular routing tasks also performs bootstraping for other nodes.

Bootstrap node runs a simple HTTP server that accepts POST request with the same payload as `COMPRESSED_CORE_COMMAND_SIGNAL` command data (see "Core commands" section above), but with target ID containing all zeroes.
Upon receiving such request, bootstrap node has 2 options:
* either consume these signaling data and generate response payload the same as `COMPRESSED_CORE_COMMAND_SIGNAL` command data
* or forward request as `COMPRESSED_CORE_COMMAND_SIGNAL` to one of its peer while replacing target ID with actual ID of a peer

In either case, response to POST HTTP request will contain:
* X bytes - payload according to `COMPRESSED_CORE_COMMAND_SIGNAL` format
* 64 bytes - ed25519 signature that corresponds to bootstrap node's key pair (which might be different from DHT key pair, so that load balancing can be applied)

This way node that joins the network can connect to 1 new node in DHT at a time using one bootstrap node.

When DHT node connects to new peer, it will send `UNCOMPRESSED_CORE_COMMAND_BOOTSTRAP_NODE` command in response with following data:
* X bytes - string in format `node_id:address:port` where `node_id` is bootstrap node's ed25519 public key, `address` and `port` can be used for HTTP connections to bootstrap node

`UNCOMPRESSED_CORE_COMMAND_BOOTSTRAP_NODE` is a way for bootstrap node to advertise to other DHT nodes that it supports bootstrapping and will not accept routing commands.

Bootstrap node doesn't provide any routing tasks, it only supports DHT commands, `UNCOMPRESSED_CORE_COMMAND_BOOTSTRAP_NODE` and `COMPRESSED_CORE_COMMAND_SIGNAL`.
Essentially, all routing features MUST be disabled and node only operates as DHT bootstrap node.

#### Router
Anonymous router is based on [Ronion](https://github.com/nazar-pc/ronion) framework, make yourself familiar with Ronion first as this document will not cover it.

Following choices were made for this particular implementation of Ronion:
* packet size is 509 bytes (512 of data channel packet - 3 for data channel packet header)
* address in 32 bytes DHT public key (see keypairs section below)
* `Noise_NK_25519_ChaChaPoly_BLAKE2b` from [Noise Protocol Framework](https://noiseprotocol.org/) is used for encryption/decryption (payload on `CREATE_REQUEST`, `CREATE_RESPONSE` and `EXTEND_REQUEST` is Noise's handshake message)
* [AEZ block cipher](http://web.cs.ucdavis.edu/%7Erogaway/aez/) is used for re-wrapping (keys for wrapping/unwrapping with AEZ are received by encrypting 32 zero bytes with empty additional data using send/receive Noise CipherState used for encryption/decryption, together with 16 bytes MAC it will give identical 48 bytes keys for wrapping and unwrapping on both sides; nonce is 12 zero bytes and before each wrapping/unwrapping it is incremented starting from the last byte and moving to the first one)
* data MUST only be sent between initiator and responder, all other data sent by other nodes on routing path MUST be ignored

Here is the list of commands supported on Router level:

| Command name                                     | Numeric value |
|--------------------------------------------------|---------------|
| ROUTING_COMMAND_ANNOUNCE                         | 0             |
| ROUTING_COMMAND_FIND_INTRODUCTION_NODES_REQUEST  | 1             |
| ROUTING_COMMAND_FIND_INTRODUCTION_NODES_RESPONSE | 2             |
| ROUTING_COMMAND_INITIALIZE_CONNECTION            | 3             |
| ROUTING_COMMAND_INTRODUCTION                     | 4             |
| ROUTING_COMMAND_CONFIRM_CONNECTION               | 5             |
| ROUTING_COMMAND_CONNECTED                        | 6             |
| ROUTING_COMMAND_DATA                             | 7             |
| ROUTING_COMMAND_PING                             | 8             |

* `ROUTING_COMMAND_ANNOUNCE` - is used for announcement node to the network (see "Announcement to the network" section below)
* `ROUTING_COMMAND_FIND_INTRODUCTION_NODES_REQUEST` - is used for requesting introduction nodes from rendezvous node (see "Discovery and connection to a friend" section below)
* `ROUTING_COMMAND_FIND_INTRODUCTION_NODES_RESPONSE` - response for `ROUTING_COMMAND_FIND_INTRODUCTION_NODES_REQUEST` (see "Discovery and connection to a friend" section below)
* `ROUTING_COMMAND_INITIALIZE_CONNECTION` - is used for instructing rendezvous node to initialize connection to target node through introduction node (see "Discovery and connection to a friend" section below)
* `ROUTING_COMMAND_INTRODUCTION` - is used by introduction node to send introduction to target node (see "Discovery and connection to a friend" section below)
* `ROUTING_COMMAND_CONFIRM_CONNECTION` - is used by target node to respond to introduction and establish connection through rendezvous node (see "Discovery and connection to a friend" section below)
* `ROUTING_COMMAND_CONNECTED` - is used by rendezvous node to confirm that connection to target node is established (see "Discovery and connection to a friend" section below)
* `ROUTING_COMMAND_DATA` - is used for data sending and forwarding (see "Sending data to a friend" section below)
* `ROUTING_COMMAND_PING` - is used for ensuring connection is still working (see "Announcement to the network" section below)

#### One-way encryption
In some cases one-way encryption is used when there is a need to send encrypted piece of data, but there is no two-way communication yet (like during connection to a friend).

In this case Noise's `Noise_N_25519_ChaChaPoly_BLAKE2b` is used and the output is as follows:
* 48 bytes Noise handshake message
* ciphertext, same length as plaintext
* 16 bytes MAC

### Selection of nodes for routing path creation
When routing path is created (see "Routing path creation" section below), we need a set of nodes through which to create this routing path.

The first node in routing path MUST be always the random node to which direct connection is already established, at the same time each new routing path MUST start from unique node (e.g. there MUST NOT be 2 routing paths started from the same node). The rest of the nodes MUST be those to which direct connections are not yet established.

Node can send `UNCOMPRESSED_CORE_COMMAND_GET_NODES_REQUEST` transport command with empty contents to the other nodes and in response it will receive `UNCOMPRESSED_CORE_COMMAND_GET_NODES_RESPONSE` transport command that contains concatenated list of up to 10 unique random IDs of nodes queried node is aware of (node SHOULD return up to 7 directly connected nodes and the rest will be nodes it is aware of).
When routing path is created, necessary number of nodes is selected from these known nodes.

TODO: This is a very naive approach and must be improved in future iterations of the spec!

### Routing path creation
Routing path creation is regular Router routing path with pair of multiplexers/demultiplexers on both sides.

Nodes for routing path are selected as described in "Selection of nodes for routing path creation" section above.

Multiplexers/demultiplexers are only used for sending and receiving data, routing commands defined in Ronion specification MUST fit into single packet with max size of 509 bytes, so that they take at most 1 data channel packet (actual size of payload that fits into single packet is 488 bytes as Routing is encrypted and has its own overhead).
In case command payload is 0 bytes, it should be replaced with zero byte payload, otherwise demultiplexer will treat it as useless padding and will discard such command.

### Announcement to the network
Announcement to the network is done anonymously through introduction nodes.

Node that wants to introduce itself to the network first creates a few routing paths to introduction nodes.

Once connections are established, node generates announcement message, which is a mutable DHT value so that:
* key is a long-term Ed25519 public key that node wants to announce itself under
* version number is Unix timestamp in seconds
* value is a concatenated IDs of all of the introduction nodes to which routing paths were created

Announcement message contains following data:
* 32 bytes - long-term Ed25519 public key
* X bytes - mutable value data structure (see "Put value" section above)

Announcement message is not published to DHT directly, instead node sends `ROUTING_COMMAND_ANNOUNCE` routing command to introduction nodes through previously created routing paths with announcement message as payload.
When node receives `ROUTING_COMMAND_ANNOUNCE` (and validates its correctness) it becomes aware that it is now acting as introduction node for someone and MUST publish to announcement message to DHT directly, also each 30 minutes introduction node MUST re-send announcement message to DHT.

Node that announced itself SHOULD send `ROUTING_COMMAND_PING` routing command with empty contents to introduction node at least once per 60 seconds to make sure connection is kept alive, otherwise routing path can be destroyed by introduction node and it will stop forwarding introductions (see "Discovery and connection to a friend" section below).

When `ROUTING_COMMAND_PING` is received, node MUST send the same `ROUTING_COMMAND_PING` routing command with empty contents back.

### Discovery and connection to a friend
Discovery and connection to a friend also happens anonymously using rendezvous node selected by the node that wants to connect and introduction node selected by a friend during announcement to the network.

First of all, node creates routing path to rendezvous node.

Once connection is established, `ROUTING_COMMAND_FIND_INTRODUCTION_NODES_REQUEST` routing command is sent to rendezvous node with data that contains long-term public key of a friend.
Rendezvous node uses DHT to find an item using long-term public key as DHT key.

Once search is done rendezvous node responds with `ROUTING_COMMAND_FIND_INTRODUCTION_NODES_RESPONSE` routing command which contains data as follows:
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

Introduction payload is created as follows:
* 32 bytes - Own long-term public key
* 32 bytes - Ed25519 public key of rendezvous node
* 32 bytes - rendezvous token (one-time randomly generated string)
* 48 bytes - Noise handshake message for end-to-end encryption with a friend (the same `Noise_NK_25519_ChaChaPoly_BLAKE2b` is used as in routing, long-term public key is used as remote public static key)
* 64 bytes - application (to be interpreted by applications on both sides of conversation, if shorter than 64 bytes MUST be padded with zeroes)
* 32 bytes - secret (to be interpreted by remote node, SHOULD be negotiated beforehand)

Once introduction message is created, it is one-way encrypted (see "One-way encryption" section above) with long-term public key of a friend.

After this `ROUTING_COMMAND_INITIALIZE_CONNECTION` routing command is sent to rendezvous node with contents as follows:
* 32 bytes - rendezvous token, the same as in introduction payload
* 32 bytes - introduction node, the same as in introduction payload
* 32 bytes - target node to which to connect, the same as was requested in `ROUTING_COMMAND_FIND_INTRODUCTION_NODES_REQUEST`
* 368 bytes - encrypted introduction message

When node receives `ROUTING_COMMAND_INITIALIZE_CONNECTION` routing command it becomes aware that it is now acting as rendezvous node for someone.
Now rendezvous node MUST connect to specified introduction node and send `UNCOMPRESSED_CORE_COMMAND_FORWARD_INTRODUCTION` transport command with contents as follows:
* 32 bytes - target node to which to connect
* 368 bytes - encrypted introduction message

When introduction node receives `UNCOMPRESSED_CORE_COMMAND_FORWARD_INTRODUCTION` transport command it will send `ROUTING_COMMAND_INTRODUCTION` routing command to target node through routing path established before `ROUTING_COMMAND_ANNOUNCE` with encrypted introduction message as contents.

When target node receives `ROUTING_COMMAND_INTRODUCTION` from one of introduction nodes it will:
* decrypt introduction message
* verify signature with introduction node ID command came from
* check if application is known and supported
* check if secret is valid taking into account ID of the node that wants to communicate

If secret and application are fine and node wants to establish communication, it will creates new routing path to rendezvous node and will sent `ROUTING_COMMAND_CONFIRM_CONNECTION` routing command with contents as follows:
* 64 bytes - Ed25519 signature of rendezvous token using node's long-term keypair
* 32 bytes - rendezvous token
* 48 bytes - Noise handshake message for end-to-end encryption with a friend (acts as responder, long-term public key is used as local private static key)

Once rendezvous node receives `ROUTING_COMMAND_CONFIRM_CONNECTION` command, it will:
* check if rendezvous token is known
* verify that signature is valid using target node ID from `ROUTING_COMMAND_INITIALIZE_CONNECTION`

If rendezvous token is known and signature is valid, rendezvous node will sent `ROUTING_COMMAND_CONFIRM_CONNECTION` routing command back to the node that sent `ROUTING_COMMAND_INITIALIZE_CONNECTION` with contents as follows:
* 64 bytes - Ed25519 signature of rendezvous token using node's long-term keypair
* 32 bytes - rendezvous token
* 48 bytes - Noise handshake message for end-to-end encryption with a friend (acts as responder, long-term public key is used as local private static key)

Once `ROUTING_COMMAND_CONFIRM_CONNECTION` is received, connection to a friend is considered established and any `ROUTING_COMMAND_DATA` routing commands received on routing paths MUST be blindly forwarded by rendezvous node to target node and back.

NOTE: When two nodes initiated connection to each other approximately at the same time, race condition is resolved by discarding connection initiated by the node whose public key is smaller (comparing bytes starting from the first one).

### Friendship requests
Friendship is not specified as special entity or something, but there is a way to make it work.

Node can create special `secret` (see "Discovery and connection to a friend" section above) that will be commonly used for friendship requests.
This way when `ROUTING_COMMAND_INTRODUCTION` routing command is received with this `secret`, application might interpret it as friendship request instead of rejecting immediately.

In case this `secret` happens to appear in hands of spammers, it can be changed and all requests with old one will be ignored. Moreover, application can have multiple such `secret`s for different purposes, so that it doesn't have to revoke all of them at once.

### Sending data to a friend
In order to make sure data packets always fit into single data channel packet multiplexing/demultiplexing is used with max data length of 65535 bytes and packet size of 472 bytes:
* 512 of data channel packet
* \- 3 for data channel packet header
* \- 16 for block-level MAC (we encrypt each block with one-way encryption, see "One-way encryption" section above, as it will be sent through rendezvous node, which MUST NOT be able to read contents)
* \- 2 for Ronion's segment ID
* \- 1 for Ronion's command
* \- 2 for Ronion's command data length
* \- 16 for Ronion's MAC

This way each encrypted block of data will be encrypted and will occupy exactly 1 data channel packet, so that even rendezvous node will not know what data of which size it forwards.

Data are send to rendezvous node using `ROUTING_COMMAND_DATA` routing command by 2 sides of the conversation and rendezvous node transparently forwards data to the other side just like if 2 friends have direct routing path between them.

Each piece of data has command and payload. Command is 1 byte unsigned integer and payload is what needs to be sent. Command interpretation and payload format depends on application.

In order to send data to a friend, node:
* concatenates command byte and payload
* multiplexes the result into chunks of 472 bytes each
* encrypts each chunk with Noise's ChiperState established using Noise handshake messages exchanged during connection process (see "Discovery and connection to a friend" section above)
* sends each encrypted chunk using `ROUTING_COMMAND_DATA` routing command to rendezvous node

When `ROUTING_COMMAND_DATA` routing command is received, node:
* decrypts contents with Noise's CipherState
* feeds the result into demultiplexer
* when demultiplexer returns data, then first byte is command and the rest is payload

### Protocol violations and errors handling
Whenever peer explicitly violates protocol (sends incorrect proof, incorrect mutable value or similar), node MUST disconnect from such peer immediately and blacklist it.

If peer violates protocol implicitly (by not responding in time, failing to forward signaling data or similar), warning with timestamp SHOULD be remembered.

High number of warnings over short period of time will also result in disconnection and blacklisting of such peer.

TODO: specification doesn't yet specify exact blacklisting timeout or detailed warnings heuristics, this will need to be defined in future versions of the specification.

### Acknowledgements
Detox is heavily inspired by [Tor](https://www.torproject.org/) and [Tox](https://tox.chat/).
