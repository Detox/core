# Detox core [![Travis CI](https://img.shields.io/travis/Detox/core/master.svg?label=Travis%20CI)](https://travis-ci.org/Detox/core)
Core library of Detox project that provides high-level APIs used when building end-user applications.

This repository contains high level design overview ([design.md](https://github.com/Detox/core/blob/master/design.md)), specification for implementors ([spec.md](https://github.com/Detox/core/blob/master/spec.md)) and reference implementation.

Essentially glues `@detox/crypto` and `@detox/transport` together and provides very simple API for connecting to and interacting with Detox network.

WARNING: INSECURE UNTIL PROVEN THE OPPOSITE!!!

This protocol and reference implementation are intended to be secure, but until proper independent audit is conducted you shouldn't consider it to actually be secure and shouldn't use in production applications.

## Why?
Rough explanation and short comparison to networks such as Tor and Loopix is given in [why.md](https://github.com/Detox/core/blob/master/why.md).

## Key features
Detox network is an overlay network that uses HTTP and WebRTC technologies under the hood and is capable of running in modern web browser (with caveat that some HTTP bootstrap nodes are still needed).

Here are a few key features that Detox network aims to offer:
* security
* strong anonymity
* robustness
* scalability

For features mentioned above we sacrifice maximum throughput, latency (to a degree) and efficiency (there is a lot of cover traffic), which makes it only suitable for low-bandwidth and relatively low-latency (few seconds) data transfers.

### Security
Relies on [The Noise Protocol Framework](https://noiseprotocol.org/), more specifically, on `Noise_NK_25519_ChaChaPoly_BLAKE2b` for end-to-end encryption.

Should be secure already (WARNING: not proven by independent cryptographer yet, so don't rely on it being actually secure!).

### Strong anonymity
Data transfer is always at constant rate, regardless of data presence and its size.

[Ronion](https://github.com/nazar-pc/ronion) anonymous routing framework with AEZ block cipher (not secure, but functionally working implementation, see [aez.wasm](https://github.com/nazar-pc/aez.wasm)) and `Noise_NK_25519_ChaChaPoly_BLAKE2b` used for anonymous routing (WARNING: not proven by independent cryptographer yet, so don't rely on it being actually secure!).
Nodes for anonymous routing will need to be somehow received from DHT, which is a challenging and currently unsolved issue.

Higher level glue is used to select introduction nodes, announce them to DHT, then on other node select rendezvous node and introduce itself using rendezvous node through introduction node to a friend.

Anonymity is implemented on architecture level, but implementation is not anonymous yet.

### Robustness
Code and its dependencies are fragile right not. Partially robustness is responsibility of the higher level consumer (for instance, there is no confirmation that data were received).

Robustness is not yet implemented yet (DHT implementation will be rewritten).

### Scalability
Scalability is based on scalability of DHT implementation (currently [WebTorrent DHT](https://github.com/nazar-pc/webtorrent-dht), which is functionally identical to BitTorrent DHT).

Should be scalable already (WARNING: not proven yet, large-scale testing is needed, DHT implementation will be rewritten).

## Major open issues
Major open issues in the order from more important to less important (the order is not strict):
* Nodes selection for anonymous routing (will likely require DHT re-implementation)
* Make AEZ implementation secure (timings attacks in particular)
* Conduct security audit for Ronion
* Conduct security audit of a project as the whole

## How to install
```
npm install @detox/core
```

## How to use
Node.js:
```javascript
var detox_core = require('@detox/core')

detox_core.ready(function () {
    // Do stuff
});
```
Browser:
```javascript
requirejs(['@detox/core'], function (detox_core) {
    detox_core.ready(function () {
        // Do stuff
    });
})
```

## API
### detox_core.ready(callback)
* `callback` - Callback function that is called when library is ready for use

### detox_core.generate_seed() : Uint8Array
Generates random seed that can be later used in `detox_core.Core` constructor.

### detox_core.Core(dht_key_seed : Uint8Array, bootstrap_nodes : Object[], ice_servers : Object[], packets_per_second = 1 : number, bucket_size = 2 : number, max_pending_segments = 10 : number, other_dht_options = {} : Object) : detox_core.Core
Constructor for Core object, offers methods for connecting to and interacting with Detox network.

* `dht_key_seed` - seed that corresponds to temporary user identity in DHT network
* `bootstrap_nodes` - array of strings in format `address:port`
* `ice_servers` - array of objects as in [RTCPeerConnection constructor](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/RTCPeerConnection)
* `packets_per_second` - packets are sent at constant rate (which together with fixed packet size of 512 bytes can be used to identify bandwidth requirements for specific connection), `1` is minimal supported rate, actual rate is negotiated between 2 sides on connection
* `bucket_size` - size of the bucket used in DHT internals (directly affects number of active WebRTC connections)
* `max_pending_segments` - How much segments can be in pending state per one address in router
* `other_dht_options` - Other internal options supported by underlying DHT implementation `webtorrent-dht`

### detox_core.Core.start_bootstrap_node(ip : string, port : number, public_address = ip : string, public_port = port : number)
Start bootstrap server (HTTP) listening on specified IP and port, optionally referred externally by specified address (like domain name) and port.

### detox_core.Core.get_bootstrap_nodes() : Object
Returns array of collected bootstrap nodes obtained during DHT operation in the same format as `bootstrap_nodes` argument in constructor.

### detox_core.Core.announce(real_key_seed : Uint8Array, number_of_introduction_nodes : number, number_of_intermediate_nodes : number) : Uint8Array|null
Announce itself to the DHT network (without this it is still possible to interact with network and connect to friends, but friends will not be able to discover this node).

Listen for events to identify when/if announcement succeeded.

* `real_key_seed` - seed that corresponds to long-term user identity for connecting with friends
* `number_of_introduction_nodes` - non-zero number of nodes that will act as introduction nodes
* `number_of_intermediate_nodes` - non-zero number of intermediate nodes between this node and introduction node (not including it) used during routing path construction for anonymity

Returns real public key or `null` in case of failure.

### detox_core.Core.connect_to(real_key_seed : Uint8Array, target_id : Uint8Array, application : Uint8Array, secret : Uint8Array, number_of_intermediate_nodes : number) : Uint8Array|null
Connecting to a friend with `target_id` and `secret`.

Listen for events to identify when/if connection succeeded. NOTE: there is no way to know if a friend refused to answer or simply not available.

* `real_key_seed` - seed that corresponds to long-term user identity for connecting with friends
* `target_id` - long-term public key of a friend
* `application` - Application-specific string up to 64 bytes that both friends should understand
* `secret` - secret that will be sent to a friend, up to 32 bytes, typically used for friend requests and identification as kind of a password
* `number_of_intermediate_nodes` - non-zero number of intermediate nodes between this node and rendezvous node (including it) used during routing path construction for anonymity

Returns real public key or `null` in case of failure.

### detox_core.Core.get_max_data_size() : number
Returns how much data can be sent at once.

NOTE: this is a maximum supported limit, because of network architecture sending large portions of data might take a lot of time.

### detox_core.Core.send_to(real_public_key : Uint8Array, target_id : Uint8Array, command : number, data : Uint8Array)
Send data to previously connected friend.

* `real_public_key` - own real long-term public key as returned by `announce()` and `connect_to()` methods
* `target_id` - long-term public key of a friend
* `command` - command for data, can be any number from the range `0..245`
* `data` - data being sent, size limit can be obtained with `get_max_data_size()` method, roughly 65KiB

### detox_core.Core.destroy()
Stops bootstrap server, destroys all connections.

### detox_core.Core.on(event: string, callback: Function) : detox_core.Core
Register event handler.

### detox_core.Core.once(event: string, callback: Function) : detox_core.Core
Register one-time event handler (just `on()` + `off()` under the hood).

### detox_core.Core.off(event: string[, callback: Function]) : detox_core.Core
Unregister event handler.

### Event: ready
No payload.
Event is fired when Core instance is ready to be used.

### Event: introduction
Payload is `data` object with properties `real_public_key`, `target_id`, `application`, `secret` and `number_of_intermediate_nodes`.
Event is fired when a `target_id` friend is asking for introduction for `real_public_key` using application `application` (exactly 64 bytes as used in `connect_to` method, if supplied application was smaller that 64 bytes then zeroes are appended) with `secret` (exactly 32 bytes as used in `connect_to` method, if supplied secret was smaller that 32 bytes then zeroes are appended).
If node decides to accept introduction and establish connection, it sets `number_of_intermediate_nodes` property to the number of intermediate nodes between this node and rendezvous node of a friend (not including it) used during routing path construction for anonymity.

### Event: data
Payload consists of four arguments: `real_public_key` (`Uint8Array`), `target_id` (`Uint8Array`), `command` (`number`) and `data` (`Uint8Array`).
Event is fired when a friend have sent data using `send_to()` method.

### Event: announcement_failed
Payload consists of two arguments: `real_public_key` (`Uint8Array`) and `reason` (`number`), which is one of `detox_core.Core.ANNOUNCEMENT_ERROR_*` constants.
Event is fired when announcement failed.

### Event: announced
Payload is a single argument `real_public_key` (`Uint8Array`). 
Event is fired when announcement succeeded.

### Event: connection_failed
Payload consists of three arguments: `real_public_key` (`Uint8Array`), `target_id` (`Uint8Array`) and `reason` (`number`), which is one of `detox_core.Core.CONNECTION_ERROR_*` constants.
Event is fired when connection to `target_id` failed.

### Event: connection_progress
Payload consists of three arguments: `real_public_key` (`Uint8Array`), `target_id` (`Uint8Array`) and `stage` (`number`), which is one of `detox_core.Core.CONNECTION_PROGRESS_*` constants.
Event is fired when there is a progress in the process of connecting to `target_id`.

### Event: connected
Payload consists of two `Uint8Array` arguments: `real_public_key` and `target_id`.
Event is fired when connection to `target_id` succeeded.

### Event: disconnected
Payload consists of two `Uint8Array` arguments: `real_public_key` and `target_id`.
Event is fired when `target_id` disconnected for whatever reason.

### Event: connected_nodes_count
Payload is a single argument `count` (`number`).
Event is fired when new node connection with DHT node is established or destroyed.

### Event: aware_of_nodes_count
Payload is a single argument `count` (`number`).
Event is fired when number of nodes in DHT about which current node is aware of changes.

### Event: routing_paths_count
Payload is a single argument `count` (`number`).
Event is fired when new routing path is established or destroyed.

### Event: application_connections_count
Payload is a single argument `count` (`number`).
Event is fired when new application connection established or destroyed.

## Contribution
Feel free to create issues and send pull requests (for big changes create an issue first and link it from the PR), they are highly appreciated!

When reading LiveScript code make sure to configure 1 tab to be 4 spaces (GitHub uses 8 by default), otherwise code might be hard to read.

## License
Implementation: Free Public License 1.0.0 / Zero Clause BSD License

https://opensource.org/licenses/FPL-1.0.0

https://tldrlegal.com/license/bsd-0-clause-license

Specification and design: public domain
