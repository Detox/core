# Detox core [![Travis CI](https://img.shields.io/travis/Detox/detox-core/master.svg?label=Travis%20CI)](https://travis-ci.org/Detox/detox-core)
Core library of Detox project that provides high-level APIs used when building end-user applications.

Essentially glues together `@detox/crypto` and `@detox/transport` together and provides very simple API for connecting to and interacting with Detox network.

WIP, kind of works, but very fragile at the moment (also see https://github.com/js-platform/node-webrtc/issues/325), don't use for anything more that light experiments.

## API
### detox_core.ready(callback)
* `callback` - Callback function that is called when library is ready for use

### detox_core.generate_seed() : Uint8Array
Generates random seed that can be later used in `detox_core.Core` constructor.

### detox_core.Core(real_key_seed : Uint8Array, dht_key_seed : Uint8Array, bootstrap_nodes : Object[], ice_servers : Object[], packets_per_second = 1 : number, bucket_size = 2 : number, max_pending_segments = 10 : number) : detox_core.Core
Constructor for Core object, offers methods for connecting to and interacting with Detox network.

* `real_key_seed` - seed that corresponds to long-term user identity for connecting with friends
* `dht_key_seed` - seed that corresponds to temporary user identity in DHT network
* `bootstrap_nodes` - array of objects with keys (all of them are required) `node_id` (DHT public key of corresponding node), `host` and `ip`
* `ice_servers` - array of objects as `config.iceServers` in [simple-peer constructor](https://github.com/feross/simple-peer#peer--new-simplepeeropts)
* `packets_per_second` - packets are sent at constant rate (which together with fixed packet size of 512 bytes can be used to identify bandwidth requirements for specific connection), `1` is minimal supported rate, actual rate is negotiated between 2 sides on connection
* `bucket_size` - size of the bucket used in DHT internals (directly affects number of active WebRTC connections)
* `max_pending_segments` - How much segments can be in pending state per one address in router

### detox_core.Core.start_bootstrap_node(ip : string, port : number)
Start bootstrap server (WebSocket) listening on specified IP and port.

### detox_core.Core.get_bootstrap_nodes() : Object
Returns array of collected bootstrap nodes obtained during DHT operation in the same format as `bootstrap_nodes` argument in constructor.

### detox_core.Core.announce(number_of_introduction_nodes : number, number_of_intermediate_nodes : number)
Announce itself to the DHT network (without this it is still possible to interact with network and connect to friends, but friends will not be able to discover this node).

Listen for events to identify when/if announcement succeeded.

* `number_of_introduction_nodes` - non-zero number of nodes that will act as introduction nodes
* `number_of_intermediate_nodes` - non-zero number of intermediate nodes between this node and introduction node (not including it) used during routing path construction for anonymity


### detox_core.Core.connect_to(target_id : Uint8Array, secret : Uint8Array, number_of_intermediate_nodes : number)
Connecting to a friend with `target_id` and `secret`.

Listen for events to identify when/if connection succeeded. NOTE: there is no way to know if a friend refused to answer or simply not available.

* `target_id` - long-term public key of a friend
* `secret` - secret that will be sent to a friend, can be arbitrary length and content, typically used for friend requests and identification as kind of a password
* `number_of_intermediate_nodes` - non-zero number of intermediate nodes between this node and rendezvous node (including it) used during routing path construction for anonymity

### detox_core.Core.get_max_data_size() : number
Returns how much data can be sent at once.

NOTE: this is a maximum supported limit, because of network architecture sending large portions of data might take a lot of time.

### detox_core.Core.send_to(target_id : Uint8Array, command : number, data : Uint8Array)
Send data to previously connected friend.

* `target_id` - long-term public key of a friend
* `command` - command for data, can be any number from the range `0..245`
* `data` - data being sent

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
Payload is `data` object with properties `target_id`, `secret` and `number_of_intermediate_nodes`.
Event is fired when a `target_id` friend is asking for introduction with `secret`.
If node decides to accept introduction and establish connection, it sets `number_of_intermediate_nodes` property to the number of intermediate nodes between this node and rendezvous node of a friend (not including it) used during routing path construction for anonymity.

### Event: data
Payload consists of three arguments: `id` (`Uint8Array`), `command` (`number`) and `data` (`Uint8Array`).
Event is fired when a friend have sent data using `send_to()` method.

### Event: announcement_failed
Payload is single argument `reason` (`number`), which is one of `detox_core.Core.ANNOUNCEMENT_ERROR_*` constants.
Event is fired when announcement failed.

### Event: announced
No payload.
Event is fired when announcement succeeded.

### Event: connection_failed
Payload consists of 2 arguments: `target_id` (`Uint8Array`) and `reason` (`number`), which is one of `detox_core.Core.CONNECTION_ERROR_*` constants.
Event is fired when connection to `target_id` failed.

### Event: connection_progress
Payload consists of 2 arguments: `target_id` (`Uint8Array`) and `stage` (`number`), which is one of `detox_core.Core.CONNECTION_PROGRESS_*` constants.
Event is fired when there is a progress in the process of connecting to `target_id`.

### Event: connected
Payload is `target_id` (`Uint8Array`).
Event is fired when connection to `target_id` succeeded.

### Event: disconnected
Payload is `target_id` (`Uint8Array`).
Event is fired when `target_id` disconnected for whatever reason.

## License
MIT, see license.txt
