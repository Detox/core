/**
 * @package   Detox core
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
const COMMAND_INTRODUCE_TO	= 0
const COMMAND_CONNECTED		= 1

const ID_LENGTH				= 32
const SIGNATURE_LENGTH		= 64
# How long node should wait for rendezvous node to receive incoming connection from intended responder
const CONNECTION_TIMEOUT	= 30

const CONNECTION_ERROR_NOT_ENOUGH_CONNECTED_NODES		= 0
const CONNECTION_ERROR_NO_INTRODUCTION_NODES			= 1
const CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT	= 2
const CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES		= 3

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
/**
 * @param {!Uint8Array}	address
 * @param {!Uint8Array}	segment_id
 *
 * @return {string}
 */
function compute_source_id (address, segment_id)
	address.join(',') + segment_id.join(',')
/**
 * @param {string}		string
 * @param {!Uint8Array}	array
 *
 * @return {boolean}
 */
function is_string_equal_to_array (string, array)
	string == array.join(',')
/**
 * @param {!Uint8Array} introduction_node
 * @param {!Uint8Array} rendezvous_node
 * @param {!Uint8Array} rendezvous_token
 * @param {!Uint8Array} secret
 *
 * @return {!Uint8Array}
 */
function create_invitation_payload (introduction_node, rendezvous_node, rendezvous_token, secret)
	new Uint8Array(ID_LENGTH * 3 + secret.length)
		..set(introduction_node)
		..set(rendezvous_node, ID_LENGTH)
		..set(rendezvous_token, ID_LENGTH * 2)
		..set(secret, ID_LENGTH * 3)

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

		@_connected_nodes		= new Map
		@_routing_paths			= new Map
		# Mapping from responder ID to routing path and from routing path to responder ID, so that we can use responder ID for external API
		@_id_to_routing_path	= new Map
		@_routing_path_to_id	= new Map
		@_used_tags				= new Map

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
				@_del_used_tag(id)
			)
			.'on'('data', (id, data) !~>
				@_router['process_packet'](id, data)
			)
		@_router
			.'on'('send', (id, data) !~>
				@_dht['send_data'](id, data)
			)
			.'on'('data', (node_id, route_id, data) !~>
				source_id	= compute_source_id(node_id, route_id)
				if !@_routing_path_to_id.has(source_id)
					# If routing path unknown - ignore
					return
				responder_id	= @_routing_path_to_id.get(source_id)
				@'fire'('data', responder_id, data)
			)
			.'on'('destroyed', !~>
				#TODO
			)
	Core
		..'CONNECTION_ERROR_NOT_ENOUGH_CONNECTED_NODES'			= CONNECTION_ERROR_NOT_ENOUGH_CONNECTED_NODES
		..'CONNECTION_ERROR_NO_INTRODUCTION_NODES'				= CONNECTION_ERROR_NO_INTRODUCTION_NODES
		..'CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT'	= CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT
		..'CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES'			= CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES
	Core:: = Object.create(async-eventer::)
	Core::
		/**
		 * @param {!Uint8Array}	id
		 * @param {!Uint8Array}	secret
		 * @param {number}		number_of_intermediate_nodes	How many hops should be made til rendezvous node
		 */
		..'connect_to' = (id, secret, number_of_intermediate_nodes) !->
			if !number_of_intermediate_nodes
				# TODO: Support direct connections here?
				return
			# Require at least twice as much nodes to be connected
			if @_connected_nodes.size / 2 < number_of_intermediate_nodes
				@'fire'('connection_failed', id, CONNECTION_ERROR_NOT_ENOUGH_CONNECTED_NODES)
				return
			@_dht['find_introduction_nodes'](
				id
				(introduction_nodes) !~>
					if !introduction_nodes.length
						@'fire'('connection_failed', id, CONNECTION_ERROR_NO_INTRODUCTION_NODES)
						return
					# TODO: add `connection_progress` event
					# TODO: This is a naive implementation, should use unknown nodes and much bigger selection
					connected_nodes	= @_connected_nodes.slice()
					nodes			=
						for i from 0 til number_of_intermediate_nodes
							pull_random_item_from_array(connected_nodes)
					first_node		= nodes[0]
					rendezvous_node	= nodes[nodes.length - 1]
					@_add_used_tag(first_node)
					@_router['construct_routing_path'](nodes)
						.then (route_id) !~>
							!~function try_to_introduce
								if !introduction_nodes.length
									@_router['destroy_routing_path'](first_node, route_id)
									@'fire'('connection_failed', id, CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES)
									return
								introduction_node	= pull_random_item_from_array(introduction_nodes)
								rendezvous_token	= randombytes(ID_LENGTH)
								invitation_payload	= create_invitation_payload(introduction_node, rendezvous_node, rendezvous_token, secret)
								signature			= detox-crypto['sign'](
									invitation_payload
									@_real_keypair['ed25519']['public']
									@_real_keypair['ed25519']['private']
								)
								x25519_public_key	= detox-crypto['convert_public_key'](id)
								invitation_message	= detox-crypto['one_way_encrypt'](
									x25519_public_key
									new Uint8Array(invitation_payload.length + signature.length)
										..set(invitation_payload)
										..set(signature, invitation_payload.length)
								)
								data				= new Uint8Array(1 + ID_LENGTH + invitation_message.length)
									..set([COMMAND_INTRODUCE_TO])
									..set(id, 1)
									..set(rendezvous_token, 1)
									..set(invitation_message, ID_LENGTH + ID_LENGTH + 1)
								first_node_string	= first_node.join(',')
								route_id_string		= route_id.join(',')
								!~function path_confirmed (node_id, route_id, data)
									if (
										!is_string_equal_to_array(first_node_string, node_id) ||
										!is_string_equal_to_array(responder_id_string, route_id) ||
										data[0] != COMMAND_CONNECTED ||
										data.subarray(1, ID_LENGTH + 1).join(',') != rendezvous_token.join(',')
									)
										return
									clearTimeout(path_confirmation_timeout)
									@_register_routing_path(id, node_id, route_id)
									@'fire'('connection_success', id)
								@_router['on']('data', path_confirmed)
								@_router['send_to'](first_node, route_id, data)
								path_confirmation_timeout	= setTimeout (!~>
									@_ronion['off']('data', path_confirmed)
									try_to_introduce()
								), CONNECTION_TIMEOUT * 1000
							try_to_introduce()
						.catch !~>
							# TODO: Retry?
							@_del_used_tag(first_node)
							@'fire'('connection_failed', id, CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT)
							return
				!~>
					@'fire'('connection_failed', id, CONNECTION_ERROR_NO_INTRODUCTION_NODES)
			)
			# TODO: Create necessary routing path to specified node ID if not done yet and fire `connected` event (maybe send intermediate events too)
		/**
		 * @param {!Uint8Array} id
		 */
		..'disconnect_from' = (id) !->
			id_string	= id.join(',')
			if !@_id_to_routing_path.has(id_string)
				return
			[node_id, route_id] = @_id_to_routing_path.get(id_string)
			@_router['destroy_routing_path'](node_id, route_id)
			@_del_used_tag(node_id)
			@_unregister_routing_path(node_id, route_id)
		/**
		 * @param {!Uint8Array} id
		 * @param {!Uint8Array} data
		 */
		..'send_to' = (id, data) !->
			id_string	= id.join(',')
			if !@_id_to_routing_path.has(id_string)
				return
			[node_id, route_id] = @_id_to_routing_path.get(id_string)
			@_router['send_data'](node_id, route_id, data)
		/**
		 * @param {!Uint8Array} responder_id	Last node in routing path, responder
		 * @param {!Uint8Array} node_id			First node in routing path, used for routing path identification
		 * @param {!Uint8Array} route_id		ID of the route on `node_id`
		 */
		.._register_routing_path = (responder_id, node_id, route_id) !->
			source_id			= compute_source_id(node_id, route_id)
			responder_id_string	= responder_id.join(',')
			if @_routing_paths.has(source_id)
				# Something went wrong, ignore
				return
			@_routing_paths.set(source_id, [node_id, route_id])
			@_id_to_routing_path.set(responder_id_string, [node_id, route_id])
			@_routing_path_to_id.set(source_id, responder_id)
		/**
		 * @param {!Uint8Array} node_id		First node in routing path, used for routing path identification
		 * @param {!Uint8Array} route_id	ID of the route on `node_id`
		 */
		.._unregister_routing_path = (node_id, route_id) !->
			source_id	= compute_source_id(node_id, route_id)
			if !@_routing_paths.has(source_id)
				return
			responder_id_string	= @_routing_path_to_id.get(source_id).join(',')
			@_routing_paths.delete(source_id)
			@_routing_path_to_id.delete(source_id)
			@_id_to_routing_path.delete(responder_id_string)
		/**
		 * @param {!Uint8Array}
		 */
		.._add_used_tag = (node_id) !->
			node_id_string	= node_id.join(',')
			value			= 0
			if @_used_tags.has(node_id_string)
				value = @_used_tags.get(node_id_string)
			++value
			@_used_tags.set(node_id_string, value)
			if value == 1
				@_dht['add_used_tag'](node_id)
		/**
		 * @param {!Uint8Array}
		 */
		.._del_used_tag = (node_id) !->
			node_id_string	= node_id.join(',')
			if !@_used_tags.has(node_id_string)
				return
			value = @_used_tags.get(node_id_string)
			--value
			if !value
				@_used_tags.del(node_id_string)
				@_dht['del_used_tag'](node_id)
			else
				@_used_tags.set(node_id_string, value)
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
