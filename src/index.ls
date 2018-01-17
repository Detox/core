/**
 * @package Detox core
 * @author  Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @license 0BSD
 */
/*
 * Implements version 0.1.0 of the specification
 */
const DHT_COMMAND_ROUTING				= 0
const DHT_COMMAND_FORWARD_INTRODUCTION	= 1
const DHT_COMMAND_GET_NODES_REQUEST		= 2
const DHT_COMMAND_GET_NODES_RESPONSE	= 3

const ROUTING_COMMAND_ANNOUNCE							= 0
const ROUTING_COMMAND_FIND_INTRODUCTION_NODES_REQUEST	= 1
const ROUTING_COMMAND_FIND_INTRODUCTION_NODES_RESPONSE	= 2
const ROUTING_COMMAND_INITIALIZE_CONNECTION				= 3
const ROUTING_COMMAND_INTRODUCTION						= 4
const ROUTING_COMMAND_CONFIRM_CONNECTION				= 5
const ROUTING_COMMAND_CONNECTED							= 6
const ROUTING_COMMAND_DATA								= 7
const ROUTING_COMMAND_PING								= 8

const ID_LENGTH						= 32
const SIGNATURE_LENGTH				= 64
# Handshake message length for Noise_NK_25519_ChaChaPoly_BLAKE2b
const HANDSHAKE_MESSAGE_LENGTH		= 48
# ChaChaPoly+BLAKE2b
const MAC_LENGTH					= 16
# Length of the application name used during introduction
const APPLICATION_LENGTH			= 64
# How long node should wait for rendezvous node to receive incoming connection from intended responder
const CONNECTION_TIMEOUT			= 30
# The same as in `@detox/transport`
const ROUTING_PATH_SEGMENT_TIMEOUT	= 10
# After specified number of seconds since last data sending or receiving connection or route is considered unused and can be closed
const LAST_USED_TIMEOUT				= 60
# Re-announce each 30 minutes
const ANNOUNCE_INTERVAL				= 30 * 60
# After 5 minutes aware of node is considered stale and needs refreshing or replacing with a new one
const STALE_AWARE_OF_NODE_TIMEOUT	= 5 * 60
# Keep at most 1000 nodes as aware of nodes
const AWARE_OF_NODES_LIMIT			= 1000
# New aware of nodes will be fetched and old refreshed each 30 seconds
const GET_MORE_NODES_INTERVAL		= 30

const CONNECTION_OK										= 0
const CONNECTION_ERROR_NO_INTRODUCTION_NODES			= 1
const CONNECTION_ERROR_CANT_FIND_INTRODUCTION_NODES		= 2
const CONNECTION_ERROR_NOT_ENOUGH_INTERMEDIATE_NODES	= 3
const CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT	= 4
const CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES		= 5

const CONNECTION_PROGRESS_CONNECTED_TO_RENDEZVOUS_NODE	= 0
const CONNECTION_PROGRESS_FOUND_INTRODUCTION_NODES		= 1
const CONNECTION_PROGRESS_INTRODUCTION_SENT				= 2

const ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONNECTED	= 0
const ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONFIRMED	= 1
const ANNOUNCEMENT_ERROR_NOT_ENOUGH_INTERMEDIATE_NODES		= 2

/**
 * Changed order of arguments and delay in seconds for convenience
 */
function timeoutSet (delay, func)
	setTimeout(func, delay * 1000)
/**
 * Changed order of arguments and delay in seconds for convenience
 */
function intervalSet (delay, func)
	setInterval(func, delay * 1000)

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
 * @template T
 *
 * @param {!Array<T>} array Returned item will be removed from this array
 *
 * @return {T}
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
 * @param {number}				code
 * @param {!Uint8Array}			target_id
 * @param {!Array<!Uint8Array>}	nodes
 *
 * @return {!Uint8Array}
 */
function compose_find_introduction_nodes_response (code, target_id, nodes)
	result	= new Uint8Array(1 + ID_LENGTH + nodes.length * ID_LENGTH)
		..set([code])
		..set(target_id, 1)
	for node, i in nodes
		result.set(node, 1 + ID_LENGTH + i * ID_LENGTH)
	result
/**
 * @param {!Uint8Array} data
 *
 * @return {!Array} [code, target_id, nodes]
 */
function parse_find_introduction_nodes_response (data)
	code		= data[0]
	target_id	= data.subarray(1, 1 + ID_LENGTH)
	nodes		= []
	data		= data.subarray(1 + ID_LENGTH)
	for i from 0 til data.length / ID_LENGTH
		nodes.push(data.subarray(i * ID_LENGTH, (i + 1) * ID_LENGTH))
	[code, target_id, nodes]
/**
 * @param {!Uint8Array} target_id
 * @param {!Uint8Array} rendezvous_node
 * @param {!Uint8Array} rendezvous_token
 * @param {!Uint8Array} handshake_message
 * @param {!Uint8Array} application
 * @param {!Uint8Array} secret
 *
 * @return {!Uint8Array}
 */
function compose_introduction_payload (target_id, rendezvous_node, rendezvous_token, handshake_message, application, secret)
	new Uint8Array(ID_LENGTH * 3 + HANDSHAKE_MESSAGE_LENGTH + APPLICATION_LENGTH + ID_LENGTH)
		..set(target_id)
		..set(rendezvous_node, ID_LENGTH)
		..set(rendezvous_token, ID_LENGTH * 2)
		..set(handshake_message, ID_LENGTH * 3)
		..set(application, ID_LENGTH * 3 + HANDSHAKE_MESSAGE_LENGTH)
		..set(secret, ID_LENGTH * 3 + HANDSHAKE_MESSAGE_LENGTH + APPLICATION_LENGTH)
/**
 * @param {!Uint8Array} introduction_payload
 *
 * @return {!Array<!Uint8Array>} [target_id, rendezvous_node, rendezvous_token, handshake_message, application, secret]
 */
function parse_introduction_payload (introduction_payload)
	target_id			= introduction_payload.subarray(0, ID_LENGTH)
	rendezvous_node		= introduction_payload.subarray(ID_LENGTH, ID_LENGTH * 2)
	rendezvous_token	= introduction_payload.subarray(ID_LENGTH * 2, ID_LENGTH * 3)
	handshake_message	= introduction_payload.subarray(ID_LENGTH * 3, ID_LENGTH * 3 + HANDSHAKE_MESSAGE_LENGTH)
	application			= introduction_payload.subarray(ID_LENGTH * 3 + HANDSHAKE_MESSAGE_LENGTH, ID_LENGTH * 3 + HANDSHAKE_MESSAGE_LENGTH + APPLICATION_LENGTH)
	secret				= introduction_payload.subarray(ID_LENGTH * 3 + HANDSHAKE_MESSAGE_LENGTH + APPLICATION_LENGTH, ID_LENGTH * 3 + HANDSHAKE_MESSAGE_LENGTH + APPLICATION_LENGTH + ID_LENGTH)
	[target_id, rendezvous_node, rendezvous_token, handshake_message, application, secret]
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
 * @return {!Array<!Uint8Array>} [rendezvous_token, introduction_node, target_id, introduction_message]
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
	new Uint8Array(SIGNATURE_LENGTH + ID_LENGTH + HANDSHAKE_MESSAGE_LENGTH)
		..set(signature)
		..set(rendezvous_token, SIGNATURE_LENGTH)
		..set(handshake_message, SIGNATURE_LENGTH + ID_LENGTH)
/**
 * @param {!Uint8Array} message
 *
 * @return {!Array<!Uint8Array>} [signature, rendezvous_token, handshake_message]
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
 * @return {!Array<!Uint8Array>} [target_id, introduction_message]
 */
function parse_introduce_to_data (message)
	target_id				= message.subarray(0, ID_LENGTH)
	introduction_message	= message.subarray(ID_LENGTH)
	[target_id, introduction_message]

function error_handler (error)
	if error instanceof Error
		console.error(error)

function Wrapper (detox-crypto, detox-transport, fixed-size-multiplexer, async-eventer)
	/**
	 * @constructor
	 *
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
	!function Core (dht_key_seed, bootstrap_nodes, ice_servers, packets_per_second = 1, bucket_size = 2, max_pending_segments = 10)
		if !(@ instanceof Core)
			return new Core(dht_key_seed, bootstrap_nodes, ice_servers, packets_per_second, bucket_size, max_pending_segments)
		async-eventer.call(@)

		@_real_keypairs	= new Map
		@_dht_keypair	= detox-crypto['create_keypair'](dht_key_seed)
		@_max_data_size	= detox-transport['MAX_DATA_SIZE']

		@_connected_nodes		= new Map
		@_aware_of_nodes		= new Map
		@_get_nodes_requested	= new Set
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
		@_encryptor_instances	= new Map
		@_multiplexers			= new Map
		@_demultiplexers		= new Map
		@_pending_sending		= new Map

		@_cleanup_interval				= intervalSet(LAST_USED_TIMEOUT, !~>
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
		)
		@_keep_announce_routes_interval	= intervalSet(LAST_USED_TIMEOUT, !~>
			@_real_keypairs.forEach ([real_keypair, number_of_introduction_nodes, number_of_intermediate_nodes, announced_to, last_announcement]) !~>
				real_public_key			= real_keypair['ed25519']['public']
				real_public_key_string	= real_public_key.join(',')
				if announced_to.size < number_of_introduction_nodes && last_announcement
					# Give at least 3x time for announcement process to complete and to announce to some node
					reannounce_if_older_than	= +(new Date) - CONNECTION_TIMEOUT * 3
					if last_announcement < reannounce_if_older_than
						@_announce(real_public_key_string)
				announced_to.forEach (introduction_node, introduction_node_string) !~>
					if !@_id_to_routing_path.has(real_public_key_string + introduction_node_string)
						return
					[node_id, route_id]	= @_id_to_routing_path.get(real_public_key_string + introduction_node_string)
					if @_send_ping(node_id, route_id)
						source_id	= compute_source_id(node_id, route_id)
						@_pending_pings.add(source_id)
		)
		@_get_more_nodes_interval		= intervalSet(GET_MORE_NODES_INTERVAL, !~>
			if @_more_nodes_needed()
				@_get_more_nodes()
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
				if @_more_nodes_needed()
					@_get_more_nodes_from(node_id)
			)
			.'on'('node_disconnected', (node_id) !~>
				node_id_string	= node_id.join(',')
				@_connected_nodes.delete(node_id_string)
				@_get_nodes_requested.delete(node_id_string)
			)
			.'on'('data', (node_id, command, data) !~>
				switch command
					case DHT_COMMAND_ROUTING
						# TODO: Bootstrap node should refuse to act as intermediate node in routing paths
						@_router['process_packet'](node_id, data)
					case DHT_COMMAND_FORWARD_INTRODUCTION
						if @_bootstrap_node
							return
						[target_id, introduction_message]	= parse_introduce_to_data(data)
						target_id_string					= target_id.join(',')
						if !@_announcements_from.has(target_id_string)
							return
						[, target_node_id, target_route_id]	= @_announcements_from.get(target_id_string)
						@_router['send_data'](target_node_id, target_route_id, ROUTING_COMMAND_INTRODUCTION, introduction_message)
					case DHT_COMMAND_GET_NODES_REQUEST
						# TODO: This is a naive implementation, can be attacked relatively easily
						nodes	= @_pick_random_connected_nodes(7) || []
						nodes	= nodes.concat(@_pick_random_aware_of_nodes(10 - nodes.length) || [])
						data	= new Uint8Array(nodes.length * ID_LENGTH)
						for node, i in nodes
							data.set(node, i * ID_LENGTH)
						@_send_to_dht_node(node_id, DHT_COMMAND_GET_NODES_RESPONSE, data)
					case DHT_COMMAND_GET_NODES_RESPONSE
						node_id_string	= node_id.join(',')
						if !@_get_nodes_requested.has(node_id_string)
							return
						@_get_nodes_requested.delete(node_id_string)
						if !data.length || data.length % ID_LENGTH != 0
							return
						number_of_nodes			= data.length / ID_LENGTH
						stale_aware_of_nodes	= @_get_stale_aware_of_nodes()
						for i from 0 til number_of_nodes
							new_node_id			= data.subarray(i * ID_LENGTH, (i + 1) * ID_LENGTH)
							new_node_id_string	= new_node_id.join(',')
							# Ignore already connected nodes and own ID or if there are enough nodes already
							if (
								is_string_equal_to_array(new_node_id_string, @_dht_keypair['ed25519']['public']) ||
								@_connected_nodes.has(new_node_id_string)
							)
								continue
							if @_aware_of_nodes.has(new_node_id_string) || @_aware_of_nodes.size < AWARE_OF_NODES_LIMIT
								@_aware_of_nodes.set(new_node_id_string, [new_node_id, +(new Date)])
							else if stale_aware_of_nodes.length
								stale_node_to_remove = pull_random_item_from_array(stale_aware_of_nodes)
								@_aware_of_nodes.delete(stale_node_to_remove)
								@_aware_of_nodes.set(new_node_id_string, [new_node_id, +(new Date)])
							else
								break
			)
			.'on'('ready', !~>
				# Make 3 random lookups on start in order to connect to some nodes
				@_dht['lookup'](randombytes(ID_LENGTH))
				@_dht['lookup'](randombytes(ID_LENGTH))
				@_dht['lookup'](randombytes(ID_LENGTH))
				@'fire'('ready')
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
						if @_bootstrap_node
							return
						public_key	= @_dht['verify_announcement_message'](data)
						if !public_key
							return
						public_key_string	= public_key.join(',')
						# If re-announcement, make sure to stop old interval
						if @_announcements_from.has(public_key_string)
							clearInterval(@_announcements_from.get(public_key_string)[3])
						announce_interval	= intervalSet(ANNOUNCE_INTERVAL, !~>
							if !@_routing_paths.has(source_id)
								return
							@_dht['publish_announcement_message'](data)
						)
						@_announcements_from.set(public_key_string, [public_key, node_id, route_id, announce_interval])
						@_dht['publish_announcement_message'](data)
					case ROUTING_COMMAND_FIND_INTRODUCTION_NODES_REQUEST
						if @_bootstrap_node
							return
						target_id	= data
						if target_id.length != ID_LENGTH
							return
						/**
						 * @param {number}				code
						 * @param {!Array<!Uint8Array>}	nodes
						 */
						send_response	= (code, nodes) !~>
							data	= compose_find_introduction_nodes_response(code, target_id, nodes)
							@_router['send_data'](node_id, route_id, ROUTING_COMMAND_FIND_INTRODUCTION_NODES_RESPONSE, data)
						@_dht['find_introduction_nodes'](
							target_id
							(introduction_nodes) !~>
								if !introduction_nodes.length
									send_response(CONNECTION_ERROR_NO_INTRODUCTION_NODES, [])
								else
									send_response(CONNECTION_OK, introduction_nodes)
							!~>
								send_response(CONNECTION_ERROR_NO_INTRODUCTION_NODES, [])
						)
					case ROUTING_COMMAND_INITIALIZE_CONNECTION
						if @_bootstrap_node
							return
						[rendezvous_token, introduction_node, target_id, introduction_message]	= parse_initialize_connection_data(data)
						rendezvous_token_string													= rendezvous_token.join(',')
						if @_pending_connection.has(rendezvous_token_string)
							# Ignore subsequent usages of the same rendezvous token
							return
						connection_timeout														= timeoutSet(CONNECTION_TIMEOUT, !~>
							@_pending_connection.delete(rendezvous_token_string)
						)
						@_pending_connection.set(rendezvous_token_string, [node_id, route_id, target_id, connection_timeout])
						@_send_to_dht_node(
							introduction_node
							DHT_COMMAND_FORWARD_INTRODUCTION
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
						[real_public_key, introduction_node]	= @_routing_path_to_id.get(source_id)
						real_public_key_string					= real_public_key.join(',')
						introduction_node_string				= introduction_node.join(',')
						if !@_real_keypairs.has(real_public_key_string)
							return
						[real_keypair, , , announced_to]	= @_real_keypairs.get(real_public_key_string)
						if !announced_to.has(introduction_node_string)
							return
						try
							introduction_message_decrypted	= detox-crypto['one_way_decrypt'](real_keypair['x25519']['private'], data)
							signature						= introduction_message_decrypted.subarray(0, SIGNATURE_LENGTH)
							introduction_payload			= introduction_message_decrypted.subarray(SIGNATURE_LENGTH)
							[
								target_id
								rendezvous_node
								rendezvous_token
								handshake_message
								application
								secret
							]								= parse_introduction_payload(introduction_payload)
							for_signature					= new Uint8Array(ID_LENGTH + introduction_payload.length)
								..set(introduction_node)
								..set(introduction_payload, ID_LENGTH)
							if !detox-crypto['verify'](signature, for_signature, target_id)
								return
							target_id_string	= target_id.join(',')
							if @_id_to_routing_path.has(real_public_key_string + target_id_string)
								# If already have connection to this node - silently ignore:
								# might be a tricky attack when DHT public key is the same as real public key
								return
							data	=
								'real_public_key'				: real_public_key
								'target_id'						: target_id
								'secret'						: secret
								'application'					: application
								'number_of_intermediate_nodes'	: null
							@'fire'('introduction', data)
								.then !~>
									number_of_intermediate_nodes	= data['number_of_intermediate_nodes']
									if !number_of_intermediate_nodes
										throw new Error('Direct connections are not yet supported')
										# TODO: Support direct connections here?
									nodes	= @_pick_nodes_for_routing_path(number_of_intermediate_nodes, [rendezvous_node])
									if !nodes
										# TODO: Retry?
										return
									nodes.push(rendezvous_node)
									first_node	= nodes[0]
									@_router['construct_routing_path'](nodes)
										.then (route_id) !~>
											encryptor_instance	= detox-crypto['Encryptor'](false, real_keypair['x25519']['private'])
											encryptor_instance['put_handshake_message'](handshake_message)
											response_handshake_message	= encryptor_instance['get_handshake_message']()
											@_encryptor_instances.set(real_public_key_string + target_id_string, encryptor_instance)
											@_register_routing_path(real_keypair['ed25519']['public'], target_id, first_node, route_id)
											signature	= detox-crypto['sign'](rendezvous_token, real_keypair['ed25519']['public'], real_keypair['ed25519']['private'])
											@_send_to_routing_node(
												real_public_key
												target_id
												ROUTING_COMMAND_CONFIRM_CONNECTION
												compose_confirm_connection_data(signature, rendezvous_token, response_handshake_message)
											)
										.catch (error) !~>
											error_handler(error)
											# TODO: Retry?
								.catch (error) !~>
									error_handler(error)
						catch error
							error_handler(error)
					case ROUTING_COMMAND_DATA
						if @_forwarding_mapping.has(source_id)
							[target_node_id, target_route_id]	= @_forwarding_mapping.get(source_id)
							@_router['send_data'](target_node_id, target_route_id, ROUTING_COMMAND_DATA, data)
						else if @_routing_path_to_id.has(source_id)
							[real_public_key, target_id]	= @_routing_path_to_id.get(source_id)
							real_public_key_string			= real_public_key.join(',')
							target_id_string				= target_id.join(',')
							encryptor_instance				= @_encryptor_instances.get(real_public_key_string + target_id_string)
							if !encryptor_instance
								return
							demultiplexer		= @_demultiplexers.get(real_public_key_string + target_id_string)
							if !demultiplexer
								return
							data_decrypted		= encryptor_instance['decrypt'](data)
							demultiplexer['feed'](data_decrypted)
							# Data are always more or equal to block size, so no need to do `while` loop
							if demultiplexer['have_more_data']()
								data_with_header	= demultiplexer['get_data']()
								command				= data_with_header[0]
								@'fire'('data', real_public_key, target_id, command, data_with_header.subarray(1))
					case ROUTING_COMMAND_PING
						if @_routing_path_to_id.has(source_id)
							if @_pending_pings.has(source_id)
								# Don't ping back if we have sent ping ourselves
								@_pending_pings.delete(source_id)
								return
						# Send ping back
						@_send_ping(node_id, route_id)
			)
		# As we wrap encrypted data into encrypted routing path, we'll have more overhead: MAC on top of encrypted block of multiplexed data
		@_max_packet_data_size	= @_router['get_max_packet_data_size']() - MAC_LENGTH # 472 bytes
	Core.'CONNECTION_ERROR_CANT_FIND_INTRODUCTION_NODES'		= CONNECTION_ERROR_CANT_FIND_INTRODUCTION_NODES
	Core.'CONNECTION_ERROR_NOT_ENOUGH_INTERMEDIATE_NODES'		= CONNECTION_ERROR_NOT_ENOUGH_INTERMEDIATE_NODES
	Core.'CONNECTION_ERROR_NO_INTRODUCTION_NODES'				= CONNECTION_ERROR_NO_INTRODUCTION_NODES
	Core.'CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT'	= CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT
	Core.'CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES'			= CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES

	Core.'CONNECTION_PROGRESS_CONNECTED_TO_RENDEZVOUS_NODE'	= CONNECTION_PROGRESS_CONNECTED_TO_RENDEZVOUS_NODE
	Core.'CONNECTION_PROGRESS_FOUND_INTRODUCTION_NODES'		= CONNECTION_PROGRESS_FOUND_INTRODUCTION_NODES
	Core.'CONNECTION_PROGRESS_INTRODUCTION_SENT'			= CONNECTION_PROGRESS_INTRODUCTION_SENT

	Core.'ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONNECTED'	= ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONNECTED
	Core.'ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONFIRMED'	= ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONFIRMED
	Core.'ANNOUNCEMENT_ERROR_NOT_ENOUGH_INTERMEDIATE_NODES'		= ANNOUNCEMENT_ERROR_NOT_ENOUGH_INTERMEDIATE_NODES
	Core:: =
		/**
		 * Start WebSocket server listening on specified ip:port, so that current node will be capable of acting as bootstrap node for other users
		 *
		 * @param {string}	ip
		 * @param {number}	port
		 */
		'start_bootstrap_node' : (ip, port) !->
			@_dht['start_bootstrap_node'](ip, port)
			@_bootstrap_node	= true
		/**
		 * Get an array of bootstrap nodes obtained during DHT operation in the same format as `bootstrap_nodes` argument in constructor
		 *
		 * @return {!Array<!Object>} Each element is an object with keys `host`, `port` and `node_id`
		 */
		'get_bootstrap_nodes' : ->
			@_dht['get_bootstrap_nodes']()
		/**
		 * @param {!Uint8Array}	real_key_seed					Seed used to generate real long-term keypair
		 * @param {number}		number_of_introduction_nodes
		 * @param {number}		number_of_intermediate_nodes	How many hops should be made until introduction node (not including it)
		 *
		 * @return {Uint8Array} Real public key or `null` in case of failure
		 */
		'announce' : (real_key_seed, number_of_introduction_nodes, number_of_intermediate_nodes) ->
			real_keypair			= detox-crypto['create_keypair'](real_key_seed)
			real_public_key			= real_keypair['ed25519']['public']
			real_public_key_string	= real_public_key.join(',')
			# Ignore repeated announcement
			if @_real_keypairs.has(real_public_key_string)
				return null
			@_real_keypairs.set(
				real_public_key_string
				[real_keypair, number_of_introduction_nodes, number_of_intermediate_nodes, new Map]
			)
			@_announce(real_public_key_string)
			real_public_key
		/**
		 * @param {string} real_public_key_string
		 */
		_announce : (real_public_key_string) !->
			[
				real_keypair
				number_of_introduction_nodes
				number_of_intermediate_nodes
				announced_to
			]								= @_real_keypairs.get(real_public_key_string)
			real_public_key					= real_keypair['ed25519']['public']
			old_introduction_nodes			= []
			announced_to.forEach (introduction_node) !->
				old_introduction_nodes.push(introduction_node)
			number_of_introduction_nodes	= number_of_introduction_nodes - old_introduction_nodes.length
			if !number_of_introduction_nodes
				return
			@_update_last_announcement(real_public_key_string, +(new Date))
			introduction_nodes				= @_pick_random_aware_of_nodes(number_of_introduction_nodes, old_introduction_nodes)
			if !introduction_nodes
				@_update_last_announcement(real_public_key_string, 1)
				@'fire'('announcement_failed', real_public_key, ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONNECTED)
				return
			introductions_pending			= number_of_introduction_nodes
			introduction_nodes_confirmed	= []
			/**
			 * @param {!Uint8Array=} introduction_node
			 */
			!~function announced (introduction_node)
				if introduction_node
					introduction_nodes_confirmed.push(introduction_node)
				--introductions_pending
				if introductions_pending
					return
				if !introduction_nodes_confirmed.length
					@_update_last_announcement(real_public_key_string, 1)
					@'fire'('announcement_failed', real_public_key, ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONFIRMED)
					return
				# Add old introduction nodes to the list
				introduction_nodes_confirmed	:= introduction_nodes_confirmed.concat(old_introduction_nodes)
				announcement_message			= @_dht['generate_announcement_message'](
					real_public_key
					real_keypair['ed25519']['private']
					introduction_nodes_confirmed
				)
				for introduction_node in introduction_nodes_confirmed
					@_send_to_routing_node(real_public_key, introduction_node, ROUTING_COMMAND_ANNOUNCE, announcement_message)
					introduction_node_string	= introduction_node.join(',')
					announced_to.set(introduction_node_string, introduction_node)
				# TODO: Check using independent routing path that announcement indeed happened
				@'fire'('announced', real_public_key)
			for let introduction_node in introduction_nodes
				nodes	= @_pick_nodes_for_routing_path(number_of_intermediate_nodes, introduction_nodes.concat(old_introduction_nodes))
				if !nodes
					@'fire'('announcement_failed', real_public_key, ANNOUNCEMENT_ERROR_NOT_ENOUGH_INTERMEDIATE_NODES)
					return
				nodes.push(introduction_node)
				first_node	= nodes[0]
				@_router['construct_routing_path'](nodes)
					.then (route_id) !~>
						@_register_routing_path(real_public_key, introduction_node, first_node, route_id)
						announced(introduction_node)
					.catch (error) !~>
						error_handler(error)
						announced()
		/**
		 * @param {string} real_public_key_string
		 * @param {number} value
		 */
		_update_last_announcement : (real_public_key_string, value) !->
			@_real_keypairs.get(real_public_key_string)[4]	= value
		/**
		 * @param {!Uint8Array}	real_key_seed					Seed used to generate real long-term keypair
		 * @param {!Uint8Array}	target_id						Real Ed25519 pubic key of interested node
		 * @param {!Uint8Array}	application						Up to 64 bytes
		 * @param {!Uint8Array}	secret							Up to 32 bytes
		 * @param {number}		number_of_intermediate_nodes	How many hops should be made until rendezvous node (including it)
		 *
		 * @return {Uint8Array} Real public key or `null` in case of failure
		 */
		'connect_to' : (real_key_seed, target_id, application, secret, number_of_intermediate_nodes) ->
			if !number_of_intermediate_nodes
				throw new Error('Direct connections are not yet supported')
				# TODO: Support direct connections here?
			real_keypair			= detox-crypto['create_keypair'](real_key_seed)
			real_public_key			= real_keypair['ed25519']['public']
			real_public_key_string	= real_public_key.join(',')
			target_id_string		= target_id.join(',')
			if @_id_to_routing_path.has(real_public_key_string + target_id_string)
				# Already connected, do nothing
				return null
			nodes	= @_pick_nodes_for_routing_path(number_of_intermediate_nodes)
			if !nodes
				@'fire'('connection_failed', real_public_key, target_id, CONNECTION_ERROR_NOT_ENOUGH_INTERMEDIATE_NODES)
				return null
			first_node		= nodes[0]
			rendezvous_node	= nodes[nodes.length - 1]
			@_router['construct_routing_path'](nodes)
				.then (route_id) !~>
					@'fire'('connection_progress', real_public_key, target_id, CONNECTION_PROGRESS_CONNECTED_TO_RENDEZVOUS_NODE)
					first_node_string	= first_node.join(',')
					route_id_string		= route_id.join(',')
					!~function found_introduction_nodes (node_id, route_id, command, data)
						if (
							!is_string_equal_to_array(first_node_string, node_id) ||
							!is_string_equal_to_array(route_id_string, route_id) ||
							command != ROUTING_COMMAND_FIND_INTRODUCTION_NODES_RESPONSE
						)
							return
						[code, target_id, introduction_nodes]	= parse_find_introduction_nodes_response(data)
						if !is_string_equal_to_array(target_id_string, target_id)
							return
						clearTimeout(find_introduction_nodes_timeout)
						if code != CONNECTION_OK
							@'fire'('connection_failed', real_public_key, target_id, code)
							return
						@'fire'('connection_progress', real_public_key, target_id, CONNECTION_PROGRESS_FOUND_INTRODUCTION_NODES)
						!~function try_to_introduce
							if !introduction_nodes.length
								@'fire'('connection_failed', real_public_key, target_id, CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES)
								return
							introduction_node				= pull_random_item_from_array(introduction_nodes)
							rendezvous_token				= randombytes(ID_LENGTH)
							x25519_public_key				= detox-crypto['convert_public_key'](target_id)
							encryptor_instance				= detox-crypto['Encryptor'](true, x25519_public_key)
							handshake_message				= encryptor_instance['get_handshake_message']()
							introduction_payload			= compose_introduction_payload(
								real_public_key
								rendezvous_node
								rendezvous_token
								handshake_message
								application
								secret
							)
							for_signature					= new Uint8Array(ID_LENGTH + introduction_payload.length)
								..set(introduction_node)
								..set(introduction_payload, ID_LENGTH)
							signature						= detox-crypto['sign'](for_signature, real_public_key, real_keypair['ed25519']['private'])
							introduction_message			= new Uint8Array(introduction_payload.length + SIGNATURE_LENGTH)
								..set(signature)
								..set(introduction_payload, SIGNATURE_LENGTH)
							introduction_message_encrypted	= detox-crypto['one_way_encrypt'](x25519_public_key, introduction_message)
							!~function path_confirmation (node_id, route_id, command, data)
								if (
									!is_string_equal_to_array(first_node_string, node_id) ||
									!is_string_equal_to_array(route_id_string, route_id) ||
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
								@_encryptor_instances.set(real_public_key_string + target_id_string, encryptor_instance)
								clearTimeout(path_confirmation_timeout)
								@_router['off']('data', path_confirmation)
								@_register_routing_path(real_public_key, target_id, node_id, route_id)
							@_router['on']('data', path_confirmation)
							@_router['send_data'](
								first_node
								route_id
								ROUTING_COMMAND_INITIALIZE_CONNECTION
								compose_initialize_connection_data(rendezvous_token, introduction_node, target_id, introduction_message_encrypted)
							)
							@'fire'('connection_progress', real_public_key, target_id, CONNECTION_PROGRESS_INTRODUCTION_SENT)
							path_confirmation_timeout	= timeoutSet(CONNECTION_TIMEOUT, !~>
								@_router['off']('data', path_confirmation)
								encryptor_instance['destroy']()
								try_to_introduce()
							)
						try_to_introduce()
					@_router['on']('data', found_introduction_nodes)
					@_router['send_data'](first_node, route_id, ROUTING_COMMAND_FIND_INTRODUCTION_NODES_REQUEST, target_id)
					find_introduction_nodes_timeout	= timeoutSet(CONNECTION_TIMEOUT, !~>
						@_router['off']('data', found_introduction_nodes)
						@'fire'('connection_failed', real_public_key, target_id, CONNECTION_ERROR_CANT_FIND_INTRODUCTION_NODES)
					)
				.catch (error) !~>
					error_handler(error)
					@'fire'('connection_failed', real_public_key, target_id, CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT)
			real_public_key
		'get_max_data_size' : ->
			@_max_data_size
		/**
		 * @param {!Uint8Array}	real_public_key	Own real long-term public key as returned by `announce()` and `connect_to()` methods
		 * @param {!Uint8Array}	target_id		Should be connected already
		 * @param {number}		command			Command from range `0..255`
		 * @param {!Uint8Array}	data			Up to 65 KiB (limit defined in `@detox/transport`)
		 */
		'send_to' : (real_public_key, target_id, command, data) !->
			real_public_key_string	= real_public_key.join(',')
			target_id_string		= target_id.join(',')
			encryptor_instance		= @_encryptor_instances.get(real_public_key_string + target_id_string)
			if !encryptor_instance || data.length > @_max_data_size
				return
			multiplexer			= @_multiplexers.get(real_public_key_string + target_id_string)
			if !multiplexer
				return
			data_with_header	= new Uint8Array(data.length + 1)
				..set([command])
				..set(data, 1)
			multiplexer['feed'](data_with_header)
			if @_pending_sending.has(real_public_key_string + target_id_string)
				# Timer is already in progress
				return
			# It might sometimes happen that we send command with small piece of data and the rest of the block is wasted. Sending data after 0 timeout
			# allows for a few synchronous `send_to` calls to share the same block if possible in order to use space more efficiently
			@_pending_sending.set(
				real_public_key_string + target_id_string
				setTimeout !~>
					@_pending_sending.delete(real_public_key_string + target_id_string)
					while multiplexer['have_more_blocks']()
						data_block				= multiplexer['get_block']()
						data_block_encrypted	= encryptor_instance['encrypt'](data_block)
						@_send_to_routing_node(real_public_key, target_id, ROUTING_COMMAND_DATA, data_block_encrypted)
			)
		'destroy' : !->
			clearInterval(@_cleanup_interval)
			clearInterval(@_keep_announce_routes_interval)
			clearInterval(@_get_more_nodes_interval)
			@_routing_paths.forEach ([node_id, route_id]) !~>
				@_unregister_routing_path(node_id, route_id)
			@_pending_connection.forEach ([, , , connection_timeout]) !~>
				clearTimeout(connection_timeout)
			@_dht['destroy']()
			@_router['destroy']()
		/**
		 * @return {boolean}
		 */
		_more_nodes_needed : ->
			!!(@_aware_of_nodes.size < AWARE_OF_NODES_LIMIT || @_get_stale_aware_of_nodes(true).length)
		/**
		 * @param {boolean=} early_exit Will return single node if present, used to check if stale nodes are present at all
		 *
		 * @return {!Array<string>}
		 */
		_get_stale_aware_of_nodes : (early_exit = false) ->
			stale_aware_of_nodes	= []
			stale_older_than		= +(new Date) - STALE_AWARE_OF_NODE_TIMEOUT * 1000
			for [node_id, date] in Array.from(@_aware_of_nodes.values())
				if date < stale_older_than
					stale_aware_of_nodes.push(node_id.join(','))
					if early_exit
						break
			stale_aware_of_nodes
		/**
		 * Request more nodes to be aware of from some of the nodes already connected to
		 */
		_get_more_nodes : !->
			nodes	= @_pick_random_connected_nodes(5)
			if !nodes
				return
			for node_id in nodes
				@_get_more_nodes_from(node_id)
		/**
		 * @param {!Uint8Array} node_id
		 */
		_get_more_nodes_from : (node_id) !->
			@_get_nodes_requested.add(node_id.join(','))
			@_send_to_dht_node(node_id, DHT_COMMAND_GET_NODES_REQUEST, new Uint8Array(0))
		/**
		 * Get some random nodes suitable for constructing routing path through them or for acting as introduction nodes
		 *
		 * @param {number}					number_of_nodes
		 * @param {!Array<!Uint8Array>=}	exclude_nodes
		 *
		 * @return {Array<!Uint8Array>} `null` if there was not enough nodes
		 */
		_pick_nodes_for_routing_path : (number_of_nodes, exclude_nodes) ->
			connected_node	= @_pick_random_connected_nodes(1, exclude_nodes)
			if !connected_node
				return null
			intermediate_nodes	= @_pick_random_aware_of_nodes(number_of_nodes - 1, exclude_nodes)
			if !intermediate_nodes
				return null
			connected_node.concat(intermediate_nodes)
		/**
		 * Get some random nodes from already connected nodes
		 *
		 * @param {number=}					up_to_number_of_nodes
		 * @param {!Array<!Uint8Array>=}	exclude_nodes
		 *
		 * @return {Array<!Uint8Array>} `null` if there is no nodes to return
		 */
		_pick_random_connected_nodes : (up_to_number_of_nodes = 1, exclude_nodes = []) ->
			if !@_connected_nodes.size
				# Make random lookup in order to fill DHT with known nodes
				@_dht['lookup'](randombytes(ID_LENGTH))
				return null
			connected_nodes	= Array.from(@_connected_nodes.values())
			for bootstrap_node in @'get_bootstrap_nodes'()
				exclude_nodes.push(bootstrap_node['node_id'])
			connected_nodes	= connected_nodes.filter (node) ->
				!(node in exclude_nodes)
			if !connected_nodes.length
				return null
			for i from 0 til up_to_number_of_nodes
				if connected_nodes.length
					pull_random_item_from_array(connected_nodes)
		/**
		 * Get some random nodes from those that current node is aware of
		 *
		 * @param {number}					number_of_nodes
		 * @param {!Array<!Uint8Array>=}	exclude_nodes
		 *
		 * @return {Array<!Uint8Array>} `null` if there was not enough nodes
		 */
		_pick_random_aware_of_nodes : (number_of_nodes, exclude_nodes) ->
			if @_aware_of_nodes.size < number_of_nodes
				return null
			aware_of_nodes	= Array.from(@_aware_of_nodes.values())
			if exclude_nodes
				aware_of_nodes	= aware_of_nodes.filter (node) ->
					!(node in exclude_nodes)
			if aware_of_nodes.length < number_of_nodes
				return null
			for i from 0 til number_of_nodes
				pull_random_item_from_array(aware_of_nodes)[0]
		/**
		 * @param {!Uint8Array} real_public_key
		 * @param {!Uint8Array} target_id		Last node in routing path, responder
		 * @param {!Uint8Array} node_id			First node in routing path, used for routing path identification
		 * @param {!Uint8Array} route_id		ID of the route on `node_id`
		 */
		_register_routing_path : (real_public_key, target_id, node_id, route_id) !->
			source_id				= compute_source_id(node_id, route_id)
			real_public_key_string	= real_public_key.join(',')
			target_id_string		= target_id.join(',')
			if @_routing_path_to_id.has(source_id)
				# Something went wrong, ignore
				return
			@_id_to_routing_path.set(real_public_key_string + target_id_string, [node_id, route_id])
			@_routing_path_to_id.set(source_id, [real_public_key, target_id])
			# Make sure each chunk after encryption will fit perfectly into DHT packet
			# Multiplexer/demultiplexer pair is not needed for introduction node, but for simplicity we'll create it anyway
			@_multiplexers.set(real_public_key_string + target_id_string, fixed-size-multiplexer['Multiplexer'](@_max_data_size, @_max_packet_data_size))
			@_demultiplexers.set(real_public_key_string + target_id_string, fixed-size-multiplexer['Demultiplexer'](@_max_data_size, @_max_packet_data_size))
			@'fire'('connected', real_public_key, target_id)
		/**
		 * @param {!Uint8Array} node_id		First node in routing path, used for routing path identification
		 * @param {!Uint8Array} route_id	ID of the route on `node_id`
		 */
		_unregister_routing_path : (node_id, route_id) !->
			source_id	= compute_source_id(node_id, route_id)
			if !@_routing_paths.has(source_id)
				return
			@_routing_paths.delete(source_id)
			@_router['destroy_routing_path'](node_id, route_id)
			@_pending_pings.delete(source_id)
			@_announcements_from.forEach ([, node_id, route_id, announce_interval], target_id_string_local) !~>
				source_id_local	= compute_source_id(node_id, route_id)
				if source_id != source_id_local
					return
				clearInterval(announce_interval)
				@_announcements_from.delete(target_id_string_local)
			if !@_routing_path_to_id.has(source_id)
				return
			[real_public_key, target_id]	= @_routing_path_to_id.get(source_id)
			real_public_key_string			= real_public_key.join(',')
			target_id_string				= target_id.join(',')
			@_routing_path_to_id.delete(source_id)
			@_id_to_routing_path.delete(real_public_key_string + target_id_string)
			if @_pending_sending.has(real_public_key_string + target_id_string)
				clearTimeout(@_pending_sending.get(real_public_key_string + target_id_string))
				@_pending_sending.delete(real_public_key_string + target_id_string)
			@_real_keypairs.forEach ([, , , announced_to]) !->
				announced_to.delete(target_id_string)
			encryptor_instance	= @_encryptor_instances.get(target_id_string)
			if encryptor_instance
				encryptor_instance['destroy']()
				@_encryptor_instances.delete(target_id_string)
			@_multiplexers.delete(target_id_string)
			@_demultiplexers.delete(target_id_string)
			@'fire'('disconnected', real_public_key, target_id)
		/**
		 * @param {!Uint8Array}	node_id
		 * @param {number}		command	0..245
		 * @param {!Uint8Array}	data
		 */
		_send_to_dht_node : (node_id, command, data) !->
			node_id_string	= node_id.join(',')
			if @_connected_nodes.has(node_id_string)
				@_update_connection_timeout(node_id)
				@_dht['send_data'](node_id, command, data)
				return
			!~function connected (node_id)
				if !is_string_equal_to_array(node_id_string, node_id)
					return
				clearTimeout(connected_timeout)
				@_dht['off']('node_connected', connected)
				@_update_connection_timeout(node_id)
				@_dht['send_data'](node_id, command, data)
			@_dht['on']('node_connected', connected)
			connected_timeout	= timeoutSet(ROUTING_PATH_SEGMENT_TIMEOUT, !~>
				@_dht['off']('node_connected', connected)
			)
			@_dht['lookup'](node_id)
		/**
		 * @param {!Uint8Array}	real_public_key
		 * @param {!Uint8Array}	target_id
		 * @param {number}		command			0..245
		 * @param {!Uint8Array}	data
		 */
		_send_to_routing_node : (real_public_key, target_id, command, data) !->
			real_public_key_string	= real_public_key.join(',')
			target_id_string		= target_id.join(',')
			if !@_id_to_routing_path.has(real_public_key_string + target_id_string)
				return
			[node_id, route_id] = @_id_to_routing_path.get(real_public_key_string + target_id_string)
			@_router['send_data'](node_id, route_id, command, data)
		/**
		 * @param {!Uint8Array} node_id
		 * @param {!Uint8Array} route_id
		 *
		 * @return {boolean} `true` if ping was sent (not necessary delivered)
		 */
		_send_ping : (node_id, route_id) ->
			source_id	= compute_source_id(node_id, route_id)
			if @_pending_pings.has(source_id) || !@_routing_paths.has(source_id)
				return false
			@_router['send_data'](node_id, route_id, ROUTING_COMMAND_PING, new Uint8Array(0))
			true
		/**
		 * @param {!Uint8Array} node_id
		 */
		_update_connection_timeout : (node_id) !->
			node_id_string	= node_id.join(',')
			if !@_connections_timeouts.has(node_id_string)
				@_add_used_tag(node_id)
			@_connections_timeouts.set(node_id_string, [+(new Date), node_id])
		/**
		 * @param {!Uint8Array} node_id
		 */
		_add_used_tag : (node_id) !->
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
		_del_used_tag : (node_id) !->
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
	Core:: = Object.assign(Object.create(async-eventer::), Core::)

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
		/**
		 * Generate random seed that can be used as keypair seed
		 *
		 * @return {!Uint8Array} 32 bytes
		 */
		'generate_seed'	: ->
			detox-crypto['create_keypair']()['seed']
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
