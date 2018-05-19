# Why?
This document aims to describe primary ideas that drive Detox development as well as major differences and design choices comparing to networks like Tor and Loopix.

### Reachability (browser environment)
Detox project aims to be reachable by as many people as possible. Anonymity heavily depends on anonymity set and as more people join the network, it is easier to blend with the crowd.
In order to achieve this, decision was made to design Detox in a way that will allow it to work in modern web browser without any additional software or configuration required.

This seems to be the first implementation of this kind, in contrast to Tor or Loopix, connection to the network is one click away from the user.

Besides obvious benefits, this also results in some drawbacks. For instance, only protocols available from user-space JavaScript in browsers like HTTP, WebSocket or WebRTC are available.
Detox uses HTTP for connection to bootstrap nodes and WebRTC for all of its communications.

### Resistance to traffic analysis (global passive adversary, GPA)
Detox network forms a single-layer mesh of nodes, where some nodes are connected to some other nodes.
Each such connection is encrypted and data are transmitted at constant rate.
Basically, Detox takes brute force approach for protection against GPA.

This is an obvious benefit, since passive observer can't differentiate whether node is just connected to the network or actually talks to anyone.
The drawback here is very limited bandwidth and potentially most of bandwidth being wasted.

Tor in comparison is vulnerable to traffic analysis, but is incomparably more efficient and can provide incomparably higher bandwidth.
Loopix with its cover traffic is also resistant to GPA.

### Initiator and responder anonymity and unobservability
Each node in Detox network has one temporary keypair (which might be permanent for bootstrap nodes) used for interacting with other nodes on DHT level and the long-term keypair (potentially multiple or zero in case of bootstrap node) for end-to-end communications.

Temporary keypair is independent from long-term keypair and is never used directly to announce long-term keypair, so that these keypairs can't be easily linked together and on next connection to the network temporary keypair will be different.

Announcement to the network consists of building routing paths (onion route) to introduction nodes.

In order to connect to responder several things are required: responder's public key and secret must be known to initiator and responder should announce itself to the network. How public key and secret are shared is out of scope of Detox network.

If public key and secret are shared in an anonymous way, responder will be anonymous not only to the network in general, but even to initiator.
Initiator can generate a fresh long-term keypair for one conversation without announcing itself to the network, in which case they will also be anonymous not only to the network in general, but also to responder.

It is inspired by Tor's hidden services, but there is nothing besides hidden services.
Comparing to Loopix there are no providers, all nodes are equally participating in routing traffic for other nodes and any particular node can't know where on routing path it is located, who is initiator and who is responder.

In contrast to both Tor and Loopix packets in Detox are fixed size and do not depend on the length of routing path, encryption/decryption on each segment is done using AEZ wide block cipher with no ciphertext expansion.
Routing paths are stateful so packet doesn't contain information about next node in routing path and routing path of length 1 and 10 will look no different.

### Online state disclosure
In order for responder to be able to receive incoming connections, it needs to announce itself to the network.
This means that adversary can query DHT for particular public key and see that the node with particular long-term public key is currently online or was online relatively recently.
Also adversary that controls introduction node will know when node with particular node ID went online or offline.

Node can choose not to announce itself to the network. In this case node will only be able to act as initiator, incoming connections will not be possible.

This is similar to the way Tor hidden services work.
Loopix in contrast has concept of providers, so providers will know when user is online or offline, but not the other nodes in the network.

### Resistance to Eclipse attack
Not implemented at this point, the plan is to use crypto-puzzles for temporary DHT keypairs, digital signatures and Loopix-like self-checks, so that public key can't be easily selected from desired range to isolate specific user.

### Resistance to Sybil attacks
Not implemented at this point, the plan is to use crypto-puzzles for temporary DHT keypairs, so that maintaining node that participates in DHT would require adaptive amount of computational resources.

### Latency
Connection from initiator to responder should take under one minute of time. Sending message with size that fits one packet should take around 1 second for each segment in routing path, but may depend on network congestion.

Without final implementation and testing of production-like deployment it is hard to tell how exactly latency compares to Tor or Loopix (which can additionally be flexible), but generally it is expected to be on the lower side.
