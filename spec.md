# Detox specification

Specification version: 0.0.1

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

* `COMMAND_DHT` means data are consumed by DHT
* `COMMAND_TAG` - is used to notify the other node that the other node is using this connection for something more than DHT so that connection SHOULD NOT be closed immediately if not used by DHT itself
* `COMMAND_UNTAG` - is used to notify the other node that this connection is not use for anything other than DHT anymore and MAY be closed is not needed for DHT
* Commands with numeric values `3..9` are reserved for future use.
* Commands with numeric values `10...255` are translated into Routing commands from range `0..245` (which are described in Routing section below)

#### DHT
DHT is based on [WebTorrent DHT](https://github.com/nazar-pc/webtorrent-dht), which is in turn based on BitTorrent DHT, make yourself familiar with BitTorrent DHT and WebTorrent DHT first as this document will not cover them.

TODO

#### Routing
Anonymous routing is based on [Ronion](https://github.com/nazar-pc/ronion) framework, make yourself familiar with Ronion first as this document will not cover it.

TODO

TODO: The rest
