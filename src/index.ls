/**
 * @package   Detox core
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
const DHT_COMMAND_ROUTING			= 0
const DHT_COMMAND_INTRODUCE_TO		= 1

const ROUTING_COMMAND_ANNOUNCE				= 0
const ROUTING_COMMAND_INITIALIZE_CONNECTION	= 1
const ROUTING_COMMAND_INTRODUCTION			= 2
const ROUTING_COMMAND_CONFIRM_CONNECTION	= 3
const ROUTING_COMMAND_CONNECTED				= 4
const ROUTING_COMMAND_DATA					= 5
const ROUTING_COMMAND_PING					= 6

const ID_LENGTH						= 32
const SIGNATURE_LENGTH				= 64
# Handshake message length for Noise_NK_25519_ChaChaPoly_BLAKE2b
const HANDSHAKE_MESSAGE_LENGTH		= 48
# ChaChaPoly+BLAKE2b
const MAC_LENGTH					= 16
# How long node should wait for rendezvous node to receive incoming connection from intended responder
const CONNECTION_TIMEOUT			= 30
# The same as in `@detox/transport`
const ROUTING_PATH_SEGMENT_TIMEOUT	= 10
# After specified number of seconds since last data sending or receiving connection or route is considered unused and can be closed
const LAST_USED_TIMEOUT				= 60
# Re-announce each 30 minutes
const ANNOUNCE_INTERVAL				= 30 * 60

const CONNECTION_ERROR_NOT_ENOUGH_CONNECTED_NODES		= 0
const CONNECTION_ERROR_NO_INTRODUCTION_NODES			= 1
const CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT	= 2
const CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES		= 3

const CONNECTION_PROGRESS_FOUND_INTRODUCTION_NODES		= 0
const CONNECTION_PROGRESS_INTRODUCTION_SENT				= 1

const ANNOUNCEMENT_ERROR_NO_SUCCESSFUL_ANNOUNCEMENTS	= 0

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
 * @param {!Uint8Array}	route_id
 *
 * @return {string}
 */
function compute_source_id (address, route_id)
	address.join(',') + route_id.join(',')
/**
 * @param {string}		string
 * @param {!Uint8Array}	array
 *
 * @return {boolean}
 */
function is_string_equal_to_array (string, array)
	string == array.join(',')
/**
 * @param {!Uint8Array} target_id
 * @param {!Uint8Array} introduction_node
 * @param {!Uint8Array} rendezvous_node
 * @param {!Uint8Array} rendezvous_token
 * @param {!Uint8Array} handshake_message
 * @param {!Uint8Array} secret
 *
 * @return {!Uint8Array}
 */
function compose_introduction_payload (target_id, introduction_node, rendezvous_node, rendezvous_token, handshake_message, secret)
	new Uint8Array(ID_LENGTH * 3 + secret.length)
		..set(target_id)
		..set(introduction_node, ID_LENGTH)
		..set(rendezvous_node, ID_LENGTH * 2)
		..set(rendezvous_token, ID_LENGTH * 3)
		..set(handshake_message, ID_LENGTH * 4)
		..set(secret, ID_LENGTH * 4 + HANDSHAKE_MESSAGE_LENGTH)
/**
 * @param {!Uint8Array} introduction_payload
 *
 * @return {!Array<Uint8Array>} [introduction_node, rendezvous_node, rendezvous_token, handshake_message, secret]
 */
function parse_introduction_payload (introduction_payload)
	target_id			= introduction_payload.subarray(0, ID_LENGTH)
	introduction_node	= introduction_payload.subarray(ID_LENGTH, ID_LENGTH * 2)
	rendezvous_node		= introduction_payload.subarray(ID_LENGTH * 2, ID_LENGTH * 3)
	rendezvous_token	= introduction_payload.subarray(ID_LENGTH * 3, ID_LENGTH * 4)
	handshake_message	= introduction_payload.subarray(ID_LENGTH * 4, ID_LENGTH * 4 + HANDSHAKE_MESSAGE_LENGTH)
	secret				= introduction_payload.subarray(ID_LENGTH * 4 + HANDSHAKE_MESSAGE_LENGTH)
	[introduction_node, rendezvous_node, rendezvous_token, handshake_message, secret]
/**
 * @param {!Uint8Array} public_key
 * @param {!Uint8Array} announcement_message
 * @param {!Uint8Array} signature
 *
 * @return {!Uint8Array}
 */
function compose_announcement_data (public_key, announcement_message, signature)
	new Uint8Array(ID_LENGTH + announcement_message.length)
		..set(public_key)
		..set(signature, ID_LENGTH)
		..set(announcement_message, ID_LENGTH + SIGNATURE_LENGTH)
/**
 * @param {!Uint8Array} message
 *
 * @return {!Array<Uint8Array>} [public_key, announcement_message, signature]
 */
function parse_announcement_data (message)
	public_key				= message.subarray(0, ID_LENGTH)
	announcement_message	= message.subarray(ID_LENGTH, ID_LENGTH + SIGNATURE_LENGTH)
	signature				= message.subarray(ID_LENGTH + SIGNATURE_LENGTH)
	[public_key, announcement_message, signature]
/**
 * @param {!Uint8Array} rendezvous_token
 * @param {!Uint8Array} introduction_node
 * @param {!Uint8Array} target_id
 * @param {!Uint8Array} introduction_message
 *
 * @return {!Uint8Array}
 */
function compose_initialize_connection_data (rendezvous_token, introduction_node, target_id, introduction_message)
	new Uint8Array(ID_LENGTH * 3 + introduction_message.length)
		..set(rendezvous_token)
		..set(introduction_node, ID_LENGTH)
		..set(target_id, ID_LENGTH * 2)
		..set(introduction_message, ID_LENGTH * 3)
/**
 * @param {!Uint8Array} message
 *
 * @return {!Array<Uint8Array>} [rendezvous_token, introduction_node, target_id, introduction_message]
 */
function parse_initialize_connection_data (message)
	rendezvous_token		= message.subarray(0, ID_LENGTH)
	introduction_node		= message.subarray(ID_LENGTH, ID_LENGTH * 2)
	target_id				= message.subarray(ID_LENGTH * 2, ID_LENGTH * 3)
	introduction_message	= message.subarray(ID_LENGTH * 3)
	[rendezvous_token, introduction_node, target_id, introduction_message]
/**
 * @param {!Uint8Array} signature
 * @param {!Uint8Array} rendezvous_token
 * @param {!Uint8Array} handshake_message
 *
 * @return {!Uint8Array}
 */
function compose_confirm_connection_data (signature, rendezvous_token, handshake_message)
	new Uint8Array(SIGNATURE_LENGTH + rendezvous_token.length)
		..set(signature)
		..set(rendezvous_token, SIGNATURE_LENGTH)
		..set(handshake_message, SIGNATURE_LENGTH + ID_LENGTH)
/**
 * @param {!Uint8Array} message
 *
 * @return {!Array<Uint8Array>} [signature, rendezvous_token, handshake_message]
 */
function parse_confirm_connection_data (message)
	signature			= message.subarray(0, SIGNATURE_LENGTH)
	rendezvous_token	= message.subarray(SIGNATURE_LENGTH, SIGNATURE_LENGTH + ID_LENGTH)
	handshake_message	= message.subarray(SIGNATURE_LENGTH + ID_LENGTH)
	[signature, rendezvous_token, handshake_message]
/**
 * @param {!Uint8Array} target_id
 * @param {!Uint8Array} introduction_message
 *
 * @return {!Uint8Array}
 */
function compose_introduce_to_data (target_id, introduction_message)
	new Uint8Array(ID_LENGTH + introduction_message.length)
		..set(target_id)
		..set(introduction_message, ID_LENGTH)
/**
 * @param {!Uint8Array} message
 *
 * @return {!Array<Uint8Array>} [target_id, introduction_message]
 */
function parse_introduce_to_data (message)
	target_id				= message.subarray(0, ID_LENGTH)
	introduction_message	= message.subarray(ID_LENGTH)
	[target_id, introduction_message]

function Wrapper (detox-crypto, detox-transport, fixed-size-multiplexer, async-eventer)
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
	 * @param {number}			packets_per_second		Each packet send in each direction has exactly the same size and packets are sent at fixed rate (>= 1)
	 * @param {number}			bucket_size
	 * @param {number}			max_pending_segments	How much routing segments can be in pending state per one address
	 *
	 * @return {!Core}
	 *
	 * @throws {Error}
	 */
	!function Core (real_key_seed, dht_key_seed, bootstrap_nodes, ice_servers, packets_per_second = 1, bucket_size = 2, max_pending_segments = 10)
		if !(@ instanceof Core)
			return new Core(real_key_seed, dht_key_seed, bootstrap_nodes, ice_servers, packets_per_second, bucket_size, max_pending_segments)
		async-eventer.call(@)

		@_real_keypair	= detox-crypto['create_keypair'](real_key_seed)
		@_dht_keypair	= detox-crypto['create_keypair'](dht_key_seed)
		@_max_data_size	= detox-transport['MAX_DATA_SIZE']

		@_connected_nodes		= new Map
		@_routing_paths			= new Map
		# Mapping from responder ID to routing path and from routing path to responder ID, so that we can use responder ID for external API
		@_id_to_routing_path	= new Map
		@_routing_path_to_id	= new Map
		@_used_tags				= new Map
		@_connections_timeouts	= new Map
		@_routes_timeouts		= new Map
		@_pending_connection	= new Map
		@_announced_to			= new Map
		@_announcements_from	= new Map
		@_forwarding_mapping	= new Map
		@_pending_pings			= new Set
		@_last_announcement		= 0
		@_encryptor_instances	= new Map
		@_multiplexers			= new Map
		@_demultiplexers		= new Map

		@_cleanup_interval				= setInterval (!~>
			unused_older_than	= +(new Date) - LAST_USED_TIMEOUT * 1000
			@_routes_timeouts.forEach (last_updated, source_id) !~>
				if last_updated < unused_older_than
					if @_routing_paths.has(source_id)
						[node_id, route_id]	= @_routing_paths.get(source_id)
						@_unregister_routing_path(node_id, route_id)
					@_routes_timeouts.delete(source_id)
			@_connections_timeouts.forEach ([last_updated, node_id], node_id_string) !~>
				if last_updated < unused_older_than
					@_del_used_tag(node_id)
					@_connections_timeouts.delete(node_id_string)
		), LAST_USED_TIMEOUT * 1000
		@_keep_announce_routes_interval	= setInterval (!~>
			@_announced_to.forEach (introduction_node, introduction_node_string) !~>
				[node_id, route_id]	= @_id_to_routing_path.get(introduction_node_string)
				if @_send_ping(node_id, route_id)
					source_id	= compute_source_id(node_id, route_id)
					@_pending_pings.add(source_id)
			if @_announced_to.size < @_number_of_introduction_nodes && @_last_announcement
				# Give at least 3x time for announcement process to complete and to announce to some node
				re-announce_if_older_than	= +(new Date) - CONNECTION_TIMEOUT * 3
				if @_last_announcement < re-announce_if_older_than
					@_announce(@_number_of_introduction_nodes, @_number_of_intermediate_nodes)
		), LAST_USED_TIMEOUT / 2 * 1000

		@_sign		= (data) ~>
			detox-crypto['sign'](
				data
				@_real_keypair['ed25519']['public']
				@_real_keypair['ed25519']['private']
			)
		@_dht		= detox-transport['DHT'](
			@_dht_keypair['ed25519']['public']
			@_dht_keypair['ed25519']['private']
			bootstrap_nodes
			ice_servers
			packets_per_second
			bucket_size
		)
			.'on'('node_connected', (node_id) !~>
				@_connected_nodes.set(node_id.join(','), node_id)
			)
			.'on'('node_disconnected', (node_id) !~>
				@_connected_nodes.delete(node_id.join(','))
			)
			.'on'('data', (node_id, command, data) !~>
				switch command
					case DHT_COMMAND_ROUTING
						@_router['process_packet'](node_id, data)
					case DHT_COMMAND_INTRODUCE_TO
						[target_id, introduction_message]	= parse_introduce_to_data(data)
						target_id_string					= target_id.join(',')
						if !@_announcements_from.has(target_id_string)
							return
						[, target_node_id, target_route_id]	= @_announcements_from.get(target_id_string)
						@_router['send_data'](target_node_id, target_route_id, ROUTING_COMMAND_INTRODUCTION, introduction_message)
			)
		@_router	= detox-transport['Router'](@_dht_keypair['x25519']['private'], max_pending_segments)
			.'on'('activity', (node_id, route_id) !~>
				source_id	= compute_source_id(node_id, route_id)
				if !@_routing_paths.has(source_id)
					@_routing_paths.set(source_id, [node_id, route_id])
				@_update_connection_timeout(node_id)
				@_routes_timeouts.set(source_id, +(new Date))
			)
			.'on'('send', (node_id, data) !~>
				@_send_to_dht_node(node_id, DHT_COMMAND_ROUTING, data)
			)
			.'on'('data', (node_id, route_id, command, data) !~>
				source_id	= compute_source_id(node_id, route_id)
				switch command
					case ROUTING_COMMAND_ANNOUNCE
						[public_key, announcement_message, signature]	= parse_announcement_data(data)
						if !detox-crypto['verify'](signature, announcement_message, public_key)
							return
						public_key_string	= public_key.join(',')
						announce_interval	= setInterval (!~>
							if !@_routing_paths.has(source_id)
								return
							@_dht['publish_announcement_message'](announcement_message)
						), ANNOUNCE_INTERVAL * 1000
						@_announcements_from.set(public_key_string, [public_key, node_id, route_id, announce_interval])
						@_dht['publish_announcement_message'](announcement_message)
					case ROUTING_COMMAND_INITIALIZE_CONNECTION
						[rendezvous_token, introduction_node, target_id, introduction_message]	= parse_initialize_connection_data(data)
						rendezvous_token_string													= rendezvous_token.join(',')
						connection_timeout														= setTimeout (!~>
							@_pending_connection.delete(rendezvous_token_string)
						), CONNECTION_TIMEOUT * 1000
						@_pending_connection.set(rendezvous_token_string, [node_id, route_id, target_id, connection_timeout])
						@_send_to_dht_node(
							introduction_node
							DHT_COMMAND_INTRODUCE_TO
							compose_introduce_to_data(target_id, introduction_message)
						)
					case ROUTING_COMMAND_CONFIRM_CONNECTION
						[signature, rendezvous_token, handshake_message]	= parse_confirm_connection_data(data)
						rendezvous_token_string								= rendezvous_token.join(',')
						if !@_pending_connection.has(rendezvous_token_string)
							return
						[target_node_id, target_route_id, target_id, connection_timeout]	= @_pending_connection.get(rendezvous_token_string)
						if !detox-crypto['verify'](signature, rendezvous_token, target_id)
							return
						clearTimeout(connection_timeout)
						@_router['send_data'](target_node_id, target_route_id, ROUTING_COMMAND_CONNECTED, data)
						target_source_id	= compute_source_id(target_node_id, target_route_id)
						@_forwarding_mapping.set(source_id, [target_node_id, target_route_id])
						@_forwarding_mapping.set(target_source_id, [node_id, route_id])
					case ROUTING_COMMAND_INTRODUCTION
						if !@_routing_path_to_id.has(source_id)
							# If routing path unknown - ignore
							return
						introduction_node			= @_routing_path_to_id.get(source_id)
						introduction_node_string	= introduction_node.join(',')
						if !@_announced_to.has(introduction_node_string)
							# We do not expect introductions on this connection
							return
						try
							introduction_message_decrypted	= detox-crypto['one_way_decrypt'](@_real_keypair['x25519']['public'], data)
							signature						= introduction_message_decrypted.subarray(0, SIGNATURE_LENGTH)
							introduction_payload			= introduction_message_decrypted.subarray(SIGNATURE_LENGTH)
							[
								target_id
								introduction_node_received
								rendezvous_node
								rendezvous_token
								handshake_message
								secret
							]								= parse_introduction_payload(introduction_payload)
							if (
								!is_string_equal_to_array(introduction_node_received.join(','), introduction_node) ||
								!detox-crypto['verify'](signature, introduction_payload, target_id)
							)
								return
							target_id_string	= target_id.join(',')
							if @_id_to_routing_path.has(target_id_string)
								# If already have connection to this node - silently ignore:
								# might be a tricky attack when DHT public key is the same as real public key
								return
							data	=
								'target_id'						: target_id
								'secret'						: secret
								'number_of_intermediate_nodes'	: null
							<~! @'fire'('introduction', data).then
							number_of_intermediate_nodes	= data['number_of_intermediate_nodes']
							if !number_of_intermediate_nodes
								throw new Error('Direct connections are not yet supported')
								# TODO: Support direct connections here?
								return
							nodes	= @_pick_random_nodes(number_of_intermediate_nodes)
							if !nodes
								# TODO: Retry?
								return
							nodes.push(rendezvous_node)
							first_node	= nodes[0]
							@_router['construct_routing_path'](nodes)
								.then (route_id) !~>
									encryptor_instance	= detox-crypto['Encryptor'](false, @_real_keypair['x25519']['private'])
									encryptor_instance['put_handshake_message'](handshake_message)
									response_handshake_message	= encryptor_instance['get_handshake_message']()
									@_encryptor_instances.set(target_id_string, encryptor_instance)
									@_register_routing_path(target_id, first_node, route_id)
									signature	= @_sign(rendezvous_token)
									@_send_to_routing_node(
										target_id
										ROUTING_COMMAND_CONFIRM_CONNECTION
										compose_confirm_connection_data(signature, rendezvous_token, response_handshake_message)
									)
								.catch !~>
									# TODO: Retry?
					case ROUTING_COMMAND_DATA
						if @_forwarding_mapping.has(source_id)
							[target_node_id, target_route_id]	= @_forwarding_mapping.get(source_id)
							@_router['send_data'](target_node_id, target_route_id, ROUTING_COMMAND_DATA, data)
						else if @_routing_path_to_id.has(source_id)
							target_id			= @_routing_path_to_id.get(source_id)
							target_id_string	= target_id.join(',')
							encryptor_instance	= @_encryptor_instances.get(target_id_string)
							if !encryptor_instance
								return
							demultiplexer		= @_demultiplexers.get(target_id_string)
							if !demultiplexer
								return
							data_decrypted		= encryptor_instance['decrypt'](data)
							demultiplexer['feed'](data_decrypted)
							# Data are always more or equal to block size, so no need to do `while` loop
							if demultiplexer['have_more_data']()
								data_with_header	= demultiplexer['get_data']()
								command				= data_with_header[0]
								@'fire'('data', target_id, command, data_with_header.subarray(1))
					case ROUTING_COMMAND_PING
						if @_routing_path_to_id.has(source_id)
							target_id			= @_routing_path_to_id.get(source_id)
							target_id_string	= target_id.join(',')
							if @_pending_pings.has(source_id)
								# Don't ping back if we have sent ping ourselves
								@_pending_pings.delete(source_id)
								return
						# Send ping back
						@_send_ping(node_id, route_id)
			)
		# As we wrap encrypted data into encrypted routing path, we'll have more overhead: 1 byte for command, 2 bytes for multiplexer and MAC on top of that
		@_max_packet_data_size	= @_router['get_max_packet_data_size']() - 1 - 2 - MAC_LENGTH # 468 bytes
	Core
		..'CONNECTION_ERROR_NOT_ENOUGH_CONNECTED_NODES'			= CONNECTION_ERROR_NOT_ENOUGH_CONNECTED_NODES
		..'CONNECTION_ERROR_NO_INTRODUCTION_NODES'				= CONNECTION_ERROR_NO_INTRODUCTION_NODES
		..'CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT'	= CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT
		..'CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES'			= CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES

		..'CONNECTION_PROGRESS_FOUND_INTRODUCTION_NODES'		= CONNECTION_PROGRESS_FOUND_INTRODUCTION_NODES
		..'CONNECTION_PROGRESS_INTRODUCTION_SENT'				= CONNECTION_PROGRESS_INTRODUCTION_SENT

		..'ANNOUNCEMENT_ERROR_NO_SUCCESSFUL_ANNOUNCEMENTS'		= ANNOUNCEMENT_ERROR_NO_SUCCESSFUL_ANNOUNCEMENTS
	Core:: = Object.create(async-eventer::)
	Core::
		/**
		 * @param {number} number_of_introduction_nodes
		 * @param {number} number_of_intermediate_nodes	How many hops should be made until introduction node (not including it)
		 */
		..'announce' = (number_of_introduction_nodes, number_of_intermediate_nodes) !->
			@_number_of_introduction_nodes	= number_of_introduction_nodes
			@_number_of_intermediate_nodes	= number_of_intermediate_nodes
			@_announce(number_of_introduction_nodes, number_of_intermediate_nodes)
		/**
		 * @param {number}
		 * @param {number}
		 */
		.._announce = (number_of_introduction_nodes, number_of_intermediate_nodes) !->
			@_last_announcement				= +(new Date)
			old_introduction_nodes			= []
			@_announced_to.forEach (introduction_node) !->
				old_introduction_nodes.push(introduction_node)
			introduction_nodes				= @_pick_random_nodes(number_of_introduction_nodes, old_introduction_nodes)
			introductions_pending			= number_of_introduction_nodes
			introduction_nodes_confirmed	= []
			!~function announced (introduction_node)
				if introduction_node
					introduction_nodes_confirmed.push(introduction_node)
				--introductions_pending
				if introductions_pending
					return
				if !introduction_nodes_confirmed.length
					@'fire'('announcement_failed', ANNOUNCEMENT_ERROR_NO_SUCCESSFUL_ANNOUNCEMENTS)
					return
				announcement_message	= @_dht['generate_announcement_message'](
					@_real_keypair['ed25519']['public']
					@_real_keypair['ed25519']['private']
					introduction_nodes_confirmed
				)
				signature				= @_sign(announcement_message)
				for introduction_node in introduction_nodes_confirmed
					@_send_to_routing_node(
						introduction_node
						ROUTING_COMMAND_ANNOUNCE
						compose_announcement_data(@_real_keypair['ed25519']['public'], announcement_message, signature)
					)
					introduction_node_string	= introduction_node.join(',')
					@_announced_to.set(introduction_node_string, introduction_node)
				@'fire'('announced')
			for let introduction_node in introduction_nodes
				nodes	= @_pick_random_nodes(number_of_intermediate_nodes, introduction_nodes.concat(old_introduction_nodes))
				if !nodes
					return
				nodes.push(introduction_node)
				first_node	= nodes[0]
				@_router['construct_routing_path'](nodes)
					.then (route_id) !~>
						@_register_routing_path(introduction_node, first_node, route_id)
						announced(introduction_node)
					.catch !~>
						announced()
		/**
		 * @param {!Uint8Array}	target_id						Real Ed25519 pubic key of interested node
		 * @param {!Uint8Array}	secret
		 * @param {number}		number_of_intermediate_nodes	How many hops should be made until rendezvous node (not including it)
		 */
		..'connect_to' = (target_id, secret, number_of_intermediate_nodes) !->
			if !number_of_intermediate_nodes
				throw new Error('Direct connections are not yet supported')
				# TODO: Support direct connections here?
				return
			target_id_string	= target_id.join(',')
			if @_id_to_routing_path.has(target_id_string)
				# Already connected, do nothing
				return
			@_dht['find_introduction_nodes'](
				target_id
				(introduction_nodes) !~>
					if !introduction_nodes.length
						@'fire'('connection_failed', target_id, CONNECTION_ERROR_NO_INTRODUCTION_NODES)
						return
					@'fire'('connection_progress', target_id, CONNECTION_PROGRESS_FOUND_INTRODUCTION_NODES)
					connected_nodes	= Array.from(@_connected_nodes.values())
					nodes			= @_pick_random_nodes(number_of_intermediate_nodes + 1) # Number of nodes doesn't include rendezvous node, hence +1
					if !nodes
						@'fire'('connection_failed', target_id, CONNECTION_ERROR_NOT_ENOUGH_CONNECTED_NODES)
						return
					first_node		= nodes[0]
					rendezvous_node	= nodes[nodes.length - 1]
					@_router['construct_routing_path'](nodes)
						.then (route_id) !~>
							!~function try_to_introduce
								if !introduction_nodes.length
									@'fire'('connection_failed', target_id, CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES)
									return
								introduction_node		= pull_random_item_from_array(introduction_nodes)
								rendezvous_token		= randombytes(ID_LENGTH)
								x25519_public_key		= detox-crypto['convert_public_key'](target_id)
								encryptor_instance		= detox-crypto['Encryptor'](true, x25519_public_key)
								handshake_message		= encryptor_instance['get_handshake_message']()
								introduction_payload	= compose_introduction_payload(
									@_real_keypair['ed25519']['public']
									introduction_node
									rendezvous_node
									rendezvous_token
									handshake_message
									secret
								)
								signature				= @_sign(introduction_payload)
								introduction_message	= detox-crypto['one_way_encrypt'](
									x25519_public_key
									new Uint8Array(introduction_payload.length + signature.length)
										..set(signature)
										..set(introduction_payload, SIGNATURE_LENGTH)
								)
								first_node_string		= first_node.join(',')
								route_id_string			= route_id.join(',')
								!~function path_confirmation (node_id, route_id, command, data)
									if (
										!is_string_equal_to_array(first_node_string, node_id) ||
										!is_string_equal_to_array(responder_id_string, route_id) ||
										command != ROUTING_COMMAND_CONNECTED
									)
										return
									[signature, rendezvous_token_received, handshake_message_received]	= parse_confirm_connection_data(data)
									if (
										rendezvous_token_received.join(',') != rendezvous_token.join(',') ||
										!detox-crypto['verify'](signature, rendezvous_token, target_id)
									)
										return
									encryptor_instance['put_handshake_message'](handshake_message_received)
									@_encryptor_instances.set(target_id_string, encryptor_instance)
									clearTimeout(path_confirmation_timeout)
									@_register_routing_path(target_id, node_id, route_id)
								@_router['on']('data', path_confirmation)
								@_router['send_data'](
									first_node
									route_id
									ROUTING_COMMAND_INITIALIZE_CONNECTION
									compose_initialize_connection_data(rendezvous_token, introduction_node, target_id, introduction_message)
								)
								@'fire'('connection_progress', target_id, CONNECTION_PROGRESS_INTRODUCTION_SENT)
								path_confirmation_timeout	= setTimeout (!~>
									@_ronion['off']('data', path_confirmation)
									encryptor_instance['destroy']()
									try_to_introduce()
								), CONNECTION_TIMEOUT * 1000
							try_to_introduce()
						.catch !~>
							@'fire'('connection_failed', target_id, CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT)
							return
				!~>
					@'fire'('connection_failed', target_id, CONNECTION_ERROR_NO_INTRODUCTION_NODES)
			)
		/**
		 * @param {!Uint8Array}	target_id	Should be connected already
		 * @param {number}		command		Command from range `0..255`
		 * @param {!Uint8Array}	data		Up to 65 KiB (limit defined in `@detox/transport`)
		 */
		..'send_to' = (target_id, command, data) !->
			target_id_string	= target_id.join(',')
			encryptor_instance	= @_encryptor_instances.get(target_id_string)
			if !encryptor_instance || data.length > @_max_data_size
				return
			multiplexer			= @_multiplexers.get(target_id_string)
			if !multiplexer
				return
			data_with_header	= new Uint8Array(data.length + 1)
				..set([command])
				..set(data, 1)
			multiplexer['feed'](data_with_header)
			while multiplexer['have_more_blocks']()
				data_block				= multiplexer['get_block']()
				data_block_encrypted	= encryptor_instance['encrypt'](data_block)
				@_send_to_routing_node(target_id, ROUTING_COMMAND_DATA, data_block_encrypted)
		..'destroy' = !->
			clearInterval(@_cleanup_interval)
			clearInterval(@_keep_announce_routes_interval)
			@_routing_paths.forEach ([node_id, route_id]) !~>
				@_unregister_routing_path(node_id, route_id)
			@_dht['destroy']()
			@_router['destroy']()
		/**
		 * Get some random nodes suitable for constructing routing path through them or for acting as introduction nodes
		 *
		 * @param {number}				number_of_nodes
		 * @param {Array<Uint8Array>}	exclude_nodes
		 *
		 * @return {Array<Uint8Array>} `null` if there was not enough nodes
		 */
		.._pick_random_nodes = (number_of_nodes, exclude_nodes = null) ->
			# Require at least 3 times as much nodes to be connected
			if @_connected_nodes.size / 3 < number_of_nodes
				return null
			# TODO: This is a naive implementation, should use unknown nodes and much bigger selection
			connected_nodes	= Array.from(@_connected_nodes.values())
			if exclude_nodes
				connected_nodes	= connected_nodes.filter (node) ->
					!(node in exclude_nodes)
			for i from 0 til number_of_nodes
				pull_random_item_from_array(connected_nodes)
		/**
		 * @param {!Uint8Array} target_id	Last node in routing path, responder
		 * @param {!Uint8Array} node_id		First node in routing path, used for routing path identification
		 * @param {!Uint8Array} route_id	ID of the route on `node_id`
		 */
		.._register_routing_path = (target_id, node_id, route_id) !->
			source_id			= compute_source_id(node_id, route_id)
			target_id_string	= target_id.join(',')
			if @_routing_path_to_id.has(source_id)
				# Something went wrong, ignore
				return
			@_id_to_routing_path.set(target_id_string, [node_id, route_id])
			@_routing_path_to_id.set(source_id, target_id)
			# Make sure each chunk after encryption will fit perfectly into DHT packet
			# Multiplexer/demultiplexer pair is not needed for introduction node, but for simplicity we'll create it anyway
			@_multiplexers.set(target_id_string, fixed-size-multiplexer['Multiplexer'](@_max_data_size, @_max_packet_data_size))
			@_demultiplexers.set(target_id_string, fixed-size-multiplexer['Demultiplexer'](@_max_data_size, @_max_packet_data_size))
			@'fire'('connected', target_id)
		/**
		 * @param {!Uint8Array} node_id		First node in routing path, used for routing path identification
		 * @param {!Uint8Array} route_id	ID of the route on `node_id`
		 */
		.._unregister_routing_path = (node_id, route_id) !->
			source_id	= compute_source_id(node_id, route_id)
			if !@_routing_paths.has(source_id)
				return
			@_routing_paths.delete(source_id)
			@_router['destroy_routing_path'](node_id, route_id)
			@_routing_path_to_id.delete(source_id)
			@_pending_pings.delete(source_id)
			target_id	= @_routing_path_to_id.get(source_id)
			if !target_id
				return
			target_id_string	= target_id.join(',')
			@_id_to_routing_path.delete(target_id_string)
			@_announced_to.delete(target_id_string)
			encryptor_instance	= @_encryptor_instances.get(target_id_string)
			if encryptor_instance
				encryptor_instance['destroy']()
				@_encryptor_instances.delete(target_id_string)
			if @_announcements_from.has(target_id_string)
				[, , , announce_interval]	= @_announcements_from.get(target_id_string)
				clearInterval(announce_interval)
				@_announcements_from.delete(target_id_string)
			@_multiplexers.delete(target_id_string)
			@_demultiplexers.delete(target_id_string)
			@'fire'('disconnected', target_id)
		/**
		 * @param {!Uint8Array}	node_id
		 * @param {number}		command	0..245
		 * @param {!Uint8Array}	data
		 */
		.._send_to_dht_node = (node_id, command, data) !->
			node_id_string	= node_id.join(',')
			if @_connected_nodes.has(node_id_string)
				@_update_connection_timeout(node_id)
				@_dht['send_data'](node_id, command, data)
				return
			!~function connected (node_id)
				if !is_string_equal_to_array(node_id_string, node_id)
					return
				clearTimeout(connected_timeout)
				@_update_connection_timeout(node_id)
				@_dht['send_data'](node_id, command, data)
			@_dht['on']('node_connected', connected)
			connected_timeout	= setTimeout (!~>
				@_dht['off']('node_connected', connected)
			), ROUTING_PATH_SEGMENT_TIMEOUT * 1000
			@_dht['lookup'](node_id)
		/**
		 * @param {!Uint8Array}	target_id
		 * @param {number}		command		0..245
		 * @param {!Uint8Array}	data
		 */
		.._send_to_routing_node = (target_id, command, data) !->
			target_id_string	= target_id.join(',')
			if !@_id_to_routing_path.has(target_id_string)
				return
			[node_id, route_id] = @_id_to_routing_path.get(target_id_string)
			@_router['send_data'](node_id, route_id, command, data)
		/**
		 * @param {!Uint8Array} node_id
		 * @param {!Uint8Array} route_id
		 *
		 * @return {boolean} `true` if ping was sent (not necessary delivered)
		 */
		.._send_ping = (node_id, route_id) ->
			source_id	= compute_source_id(node_id, route_id)
			if @_pending_pings.has(source_id) || !@_routing_paths.has(source_id)
				return false
			@_router['send_data'](node_id, route_id, ROUTING_COMMAND_PING, new Uint8Array(0))
			true
		/**
		 * @param {!Uint8Array} node_id
		 */
		.._update_connection_timeout = (node_id) !->
			node_id_string	= node_id.join(',')
			if !@_connections_timeouts.has(node_id_string)
				@_add_used_tag(node_id)
			@_connections_timeouts.set(node_id_string, [+(new Date), node_id])
		/**
		 * @param {!Uint8Array} node_id
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
		 * @param {!Uint8Array} node_id
		 */
		.._del_used_tag = (node_id) !->
			node_id_string	= node_id.join(',')
			if !@_used_tags.has(node_id_string)
				return
			value = @_used_tags.get(node_id_string)
			--value
			if !value
				@_used_tags.delete(node_id_string)
				@_dht['del_used_tag'](node_id)
			else
				@_used_tags.set(node_id_string, value)
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
	define(['@detox/crypto', '@detox/transport', 'fixed-size-multiplexer', 'async-eventer'], Wrapper)
else if typeof exports == 'object'
	# CommonJS
	module.exports = Wrapper(require('@detox/crypto'), require('@detox/transport'), require('fixed-size-multiplexer'), require('async-eventer'))
else
	# Browser globals
	@'detox_core' = Wrapper(@'detox_crypto', @'detox_transport', @'fixed_size_multiplexer', @'async_eventer')
