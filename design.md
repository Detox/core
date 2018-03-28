# Detox design

Complements specification version: 0.2.0

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

DHT is based on [WebTorrent DHT](https://github.com/nazar-pc/webtorrent-dht), which is in turn based on BitTorrent DHT, make yourself familiar with BitTorrent DHT and WebTorrent DHT first as this document will not cover them.

DHT implementation in Detox differs from WebTorrent DHT in couple of minor ways:
* WebRTC data channel used for DHT is shared with anonymous routing, so that single connection multiplexes all of the data transferred between 2 nodes
* Bootstrap node in addition to IP and port is identified by its DHT public key and during connection signature is checked to ensure WebRTC connection was made to intended node
* ID space is increased from 160 bits to 256 bits and Ed25519 public keys are used as node ID
* SHA1 hashing function is replaced by SHA3-256 to have the same size as ID space

Anonymous routing is based on [Ronion](https://github.com/nazar-pc/ronion) framework, make yourself familiar with Ronion first as this document will not cover it.

Following choices were made for this particular implementation of Ronion:
* `Noise_NK_25519_ChaChaPoly_BLAKE2b` from [Noise Protocol Framework](https://noiseprotocol.org/) is used for encryption
* [AEZ block cipher](http://web.cs.ucdavis.edu/%7Erogaway/aez/) is used for re-wrapping
* After routing path construction data are only transferred from initiator to responder and back, all messages from other nodes on routing path to initiator are ignored

### Types of key pairs
There are 2 types of key pairs in Detox: temporary (DHT) and long-term.

DHT key pair is used for DHT operation, it is typically temporary (might be permanent, but typically only for bootstrap nodes) and is not linked to long-term key pair in any way.
Long-term key pair identifies the user across sessions, public key of this key pair is used by friends to find each other.

System is designed in a way that DHT and long-term key pairs are independent and while exchanging data with friends, user's location is hidden and no one can link 2 key pairs together.

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
