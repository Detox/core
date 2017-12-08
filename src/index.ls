/**
 * @package   Detox core
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
if typeof crypto != 'undefined'
	randombytes	= (size) ->
		array = new Uint8Array(size)
		crypto.getRandomValues(array)
		array
else
	randombytes	= require('crypto').randomBytes

/**
 * @param {number} min
 * @param {number} max
 *
 * @return {number}
 */
function random_int (min, max)
	bytes			= randombytes(4)
	uint32_number	= (new Uint32Array(bytes.buffer))[0]
	Math.floor(uint32_number / 2**32 * (max - min + 1)) + min

/**
 * @param {!Array} array Returned item will be removed from this array
 *
 * @return {*}
 */
function pull_random_item_from_array (array)
	length	= array.length
	if length == 1
		array.pop()
	else
		index	= random_int(0, length - 1)
		array.splice(index, 1)[0]

function Wrapper (detox-crypto, detox-transport, async-eventer)
	/**
	 * Generate random seed that can be used as keypair seed
	 *
	 * @return {!Uint8Array} 32 bytes
	 */
	function generate_seed
		detox-crypto['create_keypair']()['seed']
	/**
	 * @constructor
	 *
	 * @param {!Uint8Array}		real_key_seed			Seed used to generate real long-term keypair
	 * @param {!Uint8Array}		dht_key_seed			Seed used to generate temporary DHT keypair
	 * @param {!Array<!Object>}	bootstrap_nodes
	 * @param {!Array<!Object>}	ice_servers
	 * @param {number}			packet_size
	 * @param {number}			packets_per_second		Each packet send in each direction has exactly the same size and packets are sent at fixed rate (>= 1)
	 * @param {number}			bucket_size
	 * @param {number}			max_pending_segments	How much routing segments can be in pending state per one address
	 *
	 * @return {!Core}
	 *
	 * @throws {Error}
	 */
	!function Core (real_key_seed, dht_key_seed, bootstrap_nodes, ice_servers, packet_size = 512, packets_per_second = 1, bucket_size = 2, max_pending_segments = 10)
		if !(@ instanceof Core)
			return new Core(real_key_seed, dht_key_seed, bootstrap_nodes, ice_servers, packet_size, packets_per_second, bucket_size, max_pending_segments)
		async-eventer.call(@)

		@_real_keypair	= detox-crypto['create_keypair'](real_key_seed)
		@_dht_keypair	= detox-crypto['create_keypair'](dht_key_seed)

		@_connected_nodes	= new Map

		@_dht		= detox-transport['DHT'](
			@_dht_keypair['ed25519']['public']
			@_dht_keypair['ed25519']['private']
			bootstrap_nodes
			ice_servers
			packet_size
			packets_per_second
			bucket_size
		)
		@_router	= detox-transport['Router'](@_dht_keypair['x25519']['private'], packet_size, max_pending_segments)
		@_dht
			.'on'('node_connected', (id) !~>
				@_connected_nodes.set(id.join(','), id)
			)
			.'on'('node_disconnected', (id) !~>
				@_connected_nodes.delete(id.join(','))
			)
			.'on'('data', (id, data) !~>
				@_router['process_packet'](id, data)
			)
		@_router
			.'on'('send', (id, data) !~>
				@_dht['send_data'](id, data)
			)
			.'on'('data', (node_id, route_id, data) !~>
				#TODO: Fire event with ID that corresponds to responder on this routing path
			)

	Core:: = Object.create(async-eventer::)
	Core::
		/**
		 * @param {!Uint8Array}	id
		 * @param {number}		number_of_intermediate_nodes	How many hops should be made til rendezvous point
		 */
		..'connect_to' = (id, number_of_intermediate_nodes) !->
			# TODO: This is a naive implementation, should use unknown nodes
			# Require at least twice as much nodes to be connected
			if @_connected_nodes.size / 2 < number_of_intermediate_nodes
				@'fire'('connection_failed') #TODO: Add reason code
				return
			@_dht['find_introduction_nodes'](
				id
				(introduction_nodes) !~>
					# TODO: add `connection_progress` event
					function try_construct_routing_path
						if !introduction_nodes.length
							@'fire'('connection_failed') #TODO: Add reason code
							return
						introduction_node	= pull_random_item_from_array(introduction_nodes)
						connected_nodes		= Array.from(@_connected_nodes.values())
						nodes				=
							for i from 0 til number_of_intermediate_nodes
								pull_random_item_from_array(connected_nodes)
						nodes.push(introduction_node)
						first_node	= nodes[0]
						@_router['construct_routing_path'](nodes)
							.then !~> # TODO: success, then talk to introduction point
							.catch(try_construct_routing_path)
					try_construct_routing_path()
				!~>
					@'fire'('connection_failed') #TODO: Add reason code
			)
			# TODO: Create necessary routing path to specified node ID if not done yet and fire `connected` event (maybe send intermediate events too)
		/**
		 * @param {!Uint8Array} id
		 */
		..'disconnect_from' = (id) !->
			#TODO: Destroy corresponding routing path
		/**
		 * @param {!Uint8Array} id		ID of the node that should receive data
		 * @param {!Uint8Array} data
		 */
		..'send_data' = (id, data) !->
			# There should be a single routing path to specified node ID and it will be used in order to send data
			# Single routing path allows us to have simpler external API and do not bother application with `segment_id` or other implementation details
			# TODO:
	Object.defineProperty(Core::, 'constructor', {enumerable: false, value: Core})
	{
		'ready'			: (callback) !->
			wait_for	= 2
			!function ready
				--wait_for
				if !wait_for
					callback()
			detox-crypto['ready'](ready)
			detox-transport['ready'](ready)
		'generate_seed'	: generate_seed
		'Core'			: Core
	}

if typeof define == 'function' && define['amd']
	# AMD
	define(['@detox/crypto', '@detox/transport', 'async-eventer'], Wrapper)
else if typeof exports == 'object'
	# CommonJS
	module.exports = Wrapper(require('@detox/crypto'), require('@detox/transport')require('async-eventer'))
else
	# Browser globals
	@'detox_core' = Wrapper(@'detox_crypto', @'detox_transport', @'async_eventer')
