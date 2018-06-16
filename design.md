# Detox design

Complements specification version: 0.5.1

Author: Nazar Mokrynskyi

License: Detox design (this document) is hereby placed in the public domain

### Introduction
This document is a high level design overview of the Detox.
The goal of this document is to give general understanding what Detox is, how it works and why it is designed the way it is.

Refer to the specification if you intend to create alternative implementation.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be interpreted as described in IETF [RFC 2119](http://www.ietf.org/rfc/rfc2119.txt).

#### Glossary
* Initiator: the node that initiates communication
* Responder: the node with which initiator wants to communicate
* Routing path: a sequence of nodes that form a path through which initiator and responder are connected and can anonymously send encrypted data
* Friend: a node that have established friendship with another node, so that these 2 nodes are friends with each other

### What Detox is
Detox is an overlay network that is intended to offer security, strong anonymity, robustness and scalability, while having relatively low latency and capable of running in modern browsers without having any additional software installed.

On the flip side it is only suitable for transferring small amounts of data and has large overhead because of constant flow of cover traffic.

### Foundation
Detox is based on DHT and anonymous (onion) routing that share the same encrypted data channel.

Transport layer in Detox is primarily based on WebRTC Data Channel, which is really the only P2P transport available in moder web browsers.
There is only one direct connection between any 2 nodes and various types of traffic (DHT, Routing, internal commands) are multiplexed through this single connection.
Constant bandwidth is used by each connection regardless of amount of useful data to be transferred. Data transfer rate is defined during node startup and doesn't change, cover traffic is sent when there is no useful data.

Transport layer is designed in a way that protects against analysis of the traffic between 2 nodes in terms of shape and rate of transferred data.

DHT is based on [ES-DHT](https://github.com/nazar-pc/es-dht) framework, make yourself familiar with ES-DHT first as this document will not cover it.

DHT implementation in Detox makes following choices on top of ES-DHT framework:
* ID space is 256 bits
* uses ed25519 public key as node ID in DHT
* uses ed25519 signatures for mutable values stored in DHT and Blake2b truncated to 256 bits for immutable values
* plugs into shared transport layer based on WebRTC
* bootstrap nodes additionally run HTTP server alongside regular DHT operations, so that other nodes can connect to them directly on startup

DHT is designed in a way that doesn't allow to choose IDs deliberately and facilitates lookups over fixed snapshot of DHT so that adversary can't generate fake nodes on the fly as lookup progresses

Anonymous routing is based on [Ronion](https://github.com/nazar-pc/ronion) framework, make yourself familiar with Ronion first as this document will not cover it.

Following choices were made for this particular implementation of Ronion:
* `Noise_NK_25519_ChaChaPoly_BLAKE2b` from [Noise Protocol Framework](https://noiseprotocol.org/) is used for encryption
* [AEZ block cipher](http://web.cs.ucdavis.edu/%7Erogaway/aez/) is used for re-wrapping
* after routing path construction data are only transferred from initiator to responder and back, all messages from other nodes on routing path to initiator are ignored
* plugs into shared transport layer based on WebRTC

Anonymous routing is designed in a way that doesn't reveal any information to nodes that provide routing tasks about initiator, responder or length of routing path, this way nodes that do routing tasks have only bare minimum of information they need to do what they are supposed to be doing.

### Types of key pairs
There are 3 types of independent key pairs in Detox: bootstrap node's key pair, DHT key pair and long-term key pair (zero or multiple).

Bootstrap node's key pair is only used by bootstrap nodes to sign their responses. It is fixed and never changes unless bootstrap node was compromised.

DHT key pair is used for DHT operation, it is typically temporary and is used for anything besides DHT. New DHT key pair is typically re-generated on each startup.

Long-term key pair identifies the user across sessions, public key of this key pair is used by friends to find each other. Bootstrap node will have no long-term key pairs and normal user can have any number of such key pairs for different purposes.

System is designed in a way that all key pairs are independent and while exchanging data with friends, user's location is hidden and no one can easily link DHT and long-term key pairs together.

### Announcement to the network and discovery/connection
In order for friends to find each other they need to know public key from long-term key pair of a friend and a secret.

Public key acts as ID and secret is a random unique string used for authentication.

Secret might be one of 2 kinds.
The first is used for friendship requests and is not unique to a friend (MAY be changed at any time to prevent unwanted friendship requests).
Once friendship is established friends generate a unique secret that they use during discovery for authentication between them, typically this secret is larger as user doesn't need to type it and is not needed to be rotated. If friendship is revoked by one friend the other one will not be able to connect using old secret and will need to request friendship again. A friend MAY notify the other one about revocation.

When the node wants to announce itself to the network it will:
* constructs one or more routing paths of desired length to nodes that will act as introduction nodes
* generates announcement message that lists all of the introduction nodes, which is regular mutable data in DHT with long-term public key as its key
* introduction nodes publish this announcement message to DHT

When a friend wants to connect to other friend it will:
* construct routing path of desired length to the node which will act as rendezvous node
* gets introduction nodes through rendezvous node
* generate invitation message that contains information about friend's long-term public key, rendezvous token, introduction node ID, encrypted and signed application name and secret for a friend together with rendezvous node ID so that friend can connect back if needed

Rendezvous node will connect to introduction node and will ask to forward introduction, after which a friend will have to choices:
* accept introduction, build another routing path of desired length to rendezvous node and ask to confirm connection with a friend
* do nothing

Routing paths lengths are selected depending on anonymity and performance requirements. Nodes MAY have no routing paths if they don't care about anonymity and might announce themselves as well as act as rendezvous nodes for themselves.

### Acknowledgements
Detox is heavily inspired by [Tor](https://www.torproject.org/) and [Tox](https://tox.chat/).
