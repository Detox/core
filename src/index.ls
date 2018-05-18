/**
 * @package Detox core
 * @author  Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @license 0BSD
 */
/*
 * Implements version 0.3.2 of the specification
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
# Re-announce each 5 minutes
const ANNOUNCE_INTERVAL				= 10 * 60
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
const CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_NODE	= 4
const CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES		= 5

const CONNECTION_PROGRESS_CONNECTED_TO_RENDEZVOUS_NODE	= 0
const CONNECTION_PROGRESS_FOUND_INTRODUCTION_NODES		= 1
const CONNECTION_PROGRESS_INTRODUCTION_SENT				= 2

const ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONNECTED	= 0
const ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONFIRMED	= 1
const ANNOUNCEMENT_ERROR_NOT_ENOUGH_INTERMEDIATE_NODES		= 2

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

function Wrapper (detox-crypto, detox-transport, detox-utils, fixed-size-multiplexer, async-eventer)
	random_bytes				= detox-utils['random_bytes']
	random_int					= detox-utils['random_int']
	pull_random_item_from_array	= detox-utils['pull_random_item_from_array']
	are_arrays_equal			= detox-utils['are_arrays_equal']
	array2hex					= detox-utils['array2hex']
	hex2array					= detox-utils['hex2array']
	concat_arrays				= detox-utils['concat_arrays']
	timeoutSet					= detox-utils['timeoutSet']
	intervalSet					= detox-utils['intervalSet']
	error_handler				= detox-utils['error_handler']
	ArrayMap					= detox-utils['ArrayMap']
	ArraySet					= detox-utils['ArraySet']
	/**
	 * @param {Uint8Array} seed
	 *
	 * @return {!Object}
	 */
	function create_keypair (seed)
		detox-crypto['create_keypair'](seed)
	/**
	 * @return {!Uint8Array}
	 */
	function fake_node_id
		create_keypair(null)['ed25519']['public']
	/**
	 * @constructor
	 *
	 * @param {!Uint8Array}		dht_key_seed			Seed used to generate temporary DHT keypair
	 * @param {!Array<!Object>}	bootstrap_nodes
	 * @param {!Array<!Object>}	ice_servers
	 * @param {number}			packets_per_second		Each packet send in each direction has exactly the same size and packets are sent at fixed rate (>= 1)
	 * @param {number}			bucket_size
	 * @param {number}			max_pending_segments	How much routing segments can be in pending state per one address
	 * @param {!Object}			other_dht_options		Other internal options supported by underlying DHT implementation `webtorrent-dht`
	 *
	 * @return {!Core}
	 *
	 * @throws {Error}
	 */
	!function Core (dht_key_seed, bootstrap_nodes, ice_servers, packets_per_second = 1, bucket_size = 2, max_pending_segments = 10, other_dht_options = {})
		if !(@ instanceof Core)
			return new Core(dht_key_seed, bootstrap_nodes, ice_servers, packets_per_second, bucket_size, max_pending_segments, other_dht_options)
		async-eventer.call(@)

		@_real_keypairs	= ArrayMap()
		@_dht_keypair	= create_keypair(dht_key_seed)
		@_max_data_size	= detox-transport['MAX_DATA_SIZE']

		@_used_first_nodes			= ArraySet()
		@_connections_in_progress	= ArrayMap()
		@_connected_nodes			= ArraySet()
		@_aware_of_nodes			= ArrayMap()
		@_get_nodes_requested		= ArraySet()
		@_routing_paths				= ArrayMap()
		# Mapping from responder ID to routing path and from routing path to responder ID, so that we can use responder ID for external API
		@_id_to_routing_path		= ArrayMap()
		@_routing_path_to_id		= ArrayMap()
		@_used_tags					= ArrayMap()
		@_connections_timeouts		= ArrayMap()
		@_routes_timeouts			= ArrayMap()
		@_pending_connection		= ArrayMap()
		@_announcements_from		= ArrayMap()
		@_forwarding_mapping		= ArrayMap()
		@_pending_pings				= ArraySet()
		@_encryptor_instances		= ArrayMap()
		@_multiplexers				= ArrayMap()
		@_demultiplexers			= ArrayMap()
		@_pending_sending			= ArrayMap()
		@_application_connections	= ArraySet()

		@_cleanup_interval				= intervalSet(LAST_USED_TIMEOUT, !~>
			# Unregister unused routing paths
			unused_older_than	= +(new Date) - LAST_USED_TIMEOUT * 1000
			@_routes_timeouts.forEach (last_updated, source_id) !~>
				if last_updated < unused_older_than
					if @_routing_paths.has(source_id)
						[node_id, route_id]	= @_routing_paths.get(source_id)
						@_unregister_routing_path(node_id, route_id)
					@_routes_timeouts.delete(source_id)
			# Un-tag connections that are no longer used
			@_connections_timeouts.forEach (last_updated, node_id) !~>
				if last_updated < unused_older_than
					@_del_used_tag(node_id)
					@_connections_timeouts.delete(node_id)
			# Remove aware of nodes that are stale for more that double of regular timeout
			super_stale_older_than	= +(new Date) - STALE_AWARE_OF_NODE_TIMEOUT * 2 * 1000
			@_aware_of_nodes.forEach (date, node_id) !~>
				if date < super_stale_older_than
					@_aware_of_nodes.delete(node_id)
		)
		# On 4/5 of the way to dropping connection
		@_keep_announce_routes_interval	= intervalSet(LAST_USED_TIMEOUT / 5 * 4, !~>
			@_real_keypairs.forEach ([real_keypair, number_of_introduction_nodes, number_of_intermediate_nodes, announced_to, last_announcement], real_public_key) !~>
				if announced_to.size < number_of_introduction_nodes && last_announcement
					# Give at least 3x time for announcement process to complete and to announce to some node
					reannounce_if_older_than	= +(new Date) - CONNECTION_TIMEOUT * 3
					if last_announcement < reannounce_if_older_than
						@_announce(real_public_key)
				announced_to.forEach (introduction_node) !~>
					full_introduction_node_id	= concat_arrays([real_public_key, introduction_node])
					[node_id, route_id]			= @_id_to_routing_path.get(full_introduction_node_id)
					if @_send_ping(node_id, route_id)
						source_id	= concat_arrays([node_id, route_id])
						@_pending_pings.add(source_id)
		)
		@_get_more_nodes_interval		= intervalSet(GET_MORE_NODES_INTERVAL, !~>
			if @_more_aware_of_nodes_needed()
				@_get_more_aware_of_nodes()
		)

		@_dht		= detox-transport['DHT'](
			@_dht_keypair['ed25519']['public']
			@_dht_keypair['ed25519']['private']
			bootstrap_nodes
			ice_servers
			packets_per_second
			bucket_size
			other_dht_options
		)
			.'on'('node_connected', (node_id) !~>
				@_connected_nodes.add(node_id)
				@_aware_of_nodes.delete(node_id)
				@'fire'('aware_of_nodes_count', @_aware_of_nodes.size)
				@'fire'('connected_nodes_count', @_connected_nodes.size)
				node_id_hex	= array2hex(node_id)
				if @_more_aware_of_nodes_needed()
					bootstrap_nodes	= @'get_bootstrap_nodes'().map (bootstrap_node) ->
						bootstrap_node['node_id']
					if !(node_id_hex in bootstrap_nodes)
						@_get_more_nodes_from(node_id)
			)
			.'on'('node_disconnected', (node_id) !~>
				@_connected_nodes.delete(node_id)
				@'fire'('connected_nodes_count', @_connected_nodes.size)
				@_get_nodes_requested.delete(node_id)
			)
			.'on'('data', (node_id, command, data) !~>
				switch command
					case DHT_COMMAND_ROUTING
						@_router['process_packet'](node_id, data)
					case DHT_COMMAND_FORWARD_INTRODUCTION
						[target_id, introduction_message]	= parse_introduce_to_data(data)
						if !@_announcements_from.has(target_id)
							return
						[target_node_id, target_route_id]	= @_announcements_from.get(target_id)
						@_send_to_routing_node_raw(target_node_id, target_route_id, ROUTING_COMMAND_INTRODUCTION, introduction_message)
					case DHT_COMMAND_GET_NODES_REQUEST
						# TODO: This is a naive implementation, can be attacked relatively easily
						nodes	= @_pick_random_connected_nodes(7) || []
						nodes	= nodes.concat(@_pick_random_aware_of_nodes(10 - nodes.length) || [])
						data	= new Uint8Array(nodes.length * ID_LENGTH)
						for node, i in nodes
							data.set(node, i * ID_LENGTH)
						@_send_to_dht_node(node_id, DHT_COMMAND_GET_NODES_RESPONSE, data)
					case DHT_COMMAND_GET_NODES_RESPONSE
						if !@_get_nodes_requested.has(node_id)
							return
						@_get_nodes_requested.delete(node_id)
						if !data.length || data.length % ID_LENGTH != 0
							return
						number_of_nodes			= data.length / ID_LENGTH
						stale_aware_of_nodes	= @_get_stale_aware_of_nodes()
						for i from 0 til number_of_nodes
							new_node_id	= data.subarray(i * ID_LENGTH, (i + 1) * ID_LENGTH)
							# Ignore already connected nodes and own ID or if there are enough nodes already
							if (
								are_arrays_equal(new_node_id, @_dht_keypair['ed25519']['public']) ||
								@_connected_nodes.has(new_node_id)
							)
								continue
							if @_aware_of_nodes.has(new_node_id) || @_aware_of_nodes.size < AWARE_OF_NODES_LIMIT
								@_aware_of_nodes.set(new_node_id, +(new Date))
								@'fire'('aware_of_nodes_count', @_aware_of_nodes.size)
							else if stale_aware_of_nodes.length
								stale_node_to_remove = pull_random_item_from_array(stale_aware_of_nodes)
								@_aware_of_nodes.delete(stale_node_to_remove)
								@_aware_of_nodes.set(new_node_id, +(new Date))
								@'fire'('aware_of_nodes_count', @_aware_of_nodes.size)
							else
								break
			)
			.'on'('ready', !~>
				# Make 3 random lookups on start in order to connect to some nodes
				# TODO: Think about regular lookups
				@_random_lookup()
				@_random_lookup()
				@_random_lookup()
				@'fire'('ready')
			)
		@_router	= detox-transport['Router'](@_dht_keypair['x25519']['private'], max_pending_segments)
			.'on'('activity', (node_id, route_id) !~>
				source_id	= concat_arrays([node_id, route_id])
				if !@_routing_paths.has(source_id)
					@_routing_paths.set(source_id, [node_id, route_id])
				@_update_connection_timeout(node_id)
				@_routes_timeouts.set(source_id, +(new Date))
			)
			.'on'('send', (node_id, data) !~>
				@_send_to_dht_node(node_id, DHT_COMMAND_ROUTING, data)
			)
			.'on'('data', (node_id, route_id, command, data) !~>
				source_id	= concat_arrays([node_id, route_id])
				switch command
					case ROUTING_COMMAND_ANNOUNCE
						public_key	= @_verify_announcement_message(data)
						if !public_key
							return
						# If re-announcement, make sure to stop old interval
						if @_announcements_from.has(public_key)
							clearInterval(@_announcements_from.get(public_key)[2])
						announce_interval	= intervalSet(ANNOUNCE_INTERVAL, !~>
							if !@_routing_paths.has(source_id)
								return
							@_publish_announcement_message(data)
						)
						@_announcements_from.set(public_key, [node_id, route_id, announce_interval])
						@_publish_announcement_message(data)
					case ROUTING_COMMAND_FIND_INTRODUCTION_NODES_REQUEST
						target_id	= data
						if target_id.length != ID_LENGTH
							return
						/**
						 * @param {number}				code
						 * @param {!Array<!Uint8Array>}	nodes
						 */
						send_response	= (code, nodes) !~>
							data	= compose_find_introduction_nodes_response(code, target_id, nodes)
							@_send_to_routing_node_raw(node_id, route_id, ROUTING_COMMAND_FIND_INTRODUCTION_NODES_RESPONSE, data)
						@_find_introduction_nodes(target_id)
							.then (introduction_nodes) !->
								if !introduction_nodes.length
									send_response(CONNECTION_ERROR_NO_INTRODUCTION_NODES, [])
								else
									send_response(CONNECTION_OK, introduction_nodes)
							.catch !->
								send_response(CONNECTION_ERROR_NO_INTRODUCTION_NODES, [])
					case ROUTING_COMMAND_INITIALIZE_CONNECTION
						[rendezvous_token, introduction_node, target_id, introduction_message]	= parse_initialize_connection_data(data)
						if @_pending_connection.has(rendezvous_token)
							# Ignore subsequent usages of the same rendezvous token
							return
						connection_timeout														= timeoutSet(CONNECTION_TIMEOUT, !~>
							@_pending_connection.delete(rendezvous_token)
						)
						@_pending_connection.set(rendezvous_token, [node_id, route_id, target_id, connection_timeout])
						@_send_to_dht_node(
							introduction_node
							DHT_COMMAND_FORWARD_INTRODUCTION
							compose_introduce_to_data(target_id, introduction_message)
						)
					case ROUTING_COMMAND_CONFIRM_CONNECTION
						[signature, rendezvous_token, handshake_message]	= parse_confirm_connection_data(data)
						if !@_pending_connection.has(rendezvous_token)
							return
						[target_node_id, target_route_id, target_id, connection_timeout]	= @_pending_connection.get(rendezvous_token)
						if !detox-crypto['verify'](signature, rendezvous_token, target_id)
							return
						@_pending_connection.delete(rendezvous_token)
						clearTimeout(connection_timeout)
						@_send_to_routing_node_raw(target_node_id, target_route_id, ROUTING_COMMAND_CONNECTED, data)
						target_source_id	= concat_arrays([target_node_id, target_route_id])
						# TODO: There is no cleanup for these
						@_forwarding_mapping.set(source_id, [target_node_id, target_route_id])
						@_forwarding_mapping.set(target_source_id, [node_id, route_id])
					case ROUTING_COMMAND_INTRODUCTION
						if !@_routing_path_to_id.has(source_id)
							# If routing path unknown - ignore
							return
						[real_public_key, introduction_node]	= @_routing_path_to_id.get(source_id)
						if !@_real_keypairs.has(real_public_key)
							return
						[real_keypair, , , announced_to]	= @_real_keypairs.get(real_public_key)
						if !announced_to.has(introduction_node)
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
							full_target_id	= concat_arrays([real_public_key, target_id])
							if @_id_to_routing_path.has(full_target_id)
								# If already have connection to this node - silently ignore:
								# might be a tricky attack when DHT public key is the same as real public key
								return
							if @_connections_in_progress.has(full_target_id)
								connection_in_progress	= @_connections_in_progress.get(full_target_id)
								if connection_in_progress.initiator && !connection_in_progress.discarded
									for item, key in real_public_key
										if item == target_id[key]
											continue
										if item > target_id[key]
											# If this node's public_key if bigger, then connection initiated by this node will win and the other side will
											# discard its initiated connection
											return
										else
											# Otherwise our connection is discarded and we proceed with connection initiated by the other side
											connection_in_progress.discarded	= true
											break
							else
								connection_in_progress	=
									initiator	: false
								@_connections_in_progress.set(full_target_id, connection_in_progress)
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
									@_construct_routing_path(nodes)
										.then (route_id) !~>
											encryptor_instance	= detox-crypto['Encryptor'](false, real_keypair['x25519']['private'])
											encryptor_instance['put_handshake_message'](handshake_message)
											response_handshake_message	= encryptor_instance['get_handshake_message']()
											@_encryptor_instances.set(full_target_id, encryptor_instance)
											@_register_routing_path(real_public_key, target_id, first_node, route_id)
											@_connections_in_progress.delete(full_target_id)
											@_register_application_connection(real_public_key, target_id)
											signature	= detox-crypto['sign'](rendezvous_token, real_public_key, real_keypair['ed25519']['private'])
											@_send_to_routing_node(
												real_public_key
												target_id
												ROUTING_COMMAND_CONFIRM_CONNECTION
												compose_confirm_connection_data(signature, rendezvous_token, response_handshake_message)
											)
										.catch (error) !~>
											error_handler(error)
											# TODO: Retry?
											@_connections_in_progress.delete(full_target_id)
											if connection_in_progress.initiator && connection_in_progress.discarded
												@'fire'('connection_failed', real_public_key, target_id, CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_NODE)
								.catch (error) !~>
									error_handler(error)
									@_connections_in_progress.delete(full_target_id)
									if connection_in_progress.initiator && connection_in_progress.discarded
										@'fire'('connection_failed', real_public_key, target_id, CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_NODE)
						catch error
							error_handler(error)
					case ROUTING_COMMAND_DATA
						if @_forwarding_mapping.has(source_id)
							[target_node_id, target_route_id]	= @_forwarding_mapping.get(source_id)
							@_send_to_routing_node_raw(target_node_id, target_route_id, ROUTING_COMMAND_DATA, data)
						else if @_routing_path_to_id.has(source_id)
							[real_public_key, target_id]	= @_routing_path_to_id.get(source_id)
							full_target_id					= concat_arrays([real_public_key, target_id])
							encryptor_instance				= @_encryptor_instances.get(full_target_id)
							if !encryptor_instance
								return
							demultiplexer		= @_demultiplexers.get(full_target_id)
							if !demultiplexer
								return
							data_decrypted		= encryptor_instance['decrypt'](data)
							demultiplexer['feed'](data_decrypted)
							while demultiplexer['have_more_data']()
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
	Core.'CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_NODE'		= CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_NODE
	Core.'CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES'			= CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES

	Core.'CONNECTION_PROGRESS_CONNECTED_TO_RENDEZVOUS_NODE'	= CONNECTION_PROGRESS_CONNECTED_TO_RENDEZVOUS_NODE
	Core.'CONNECTION_PROGRESS_FOUND_INTRODUCTION_NODES'		= CONNECTION_PROGRESS_FOUND_INTRODUCTION_NODES
	Core.'CONNECTION_PROGRESS_INTRODUCTION_SENT'			= CONNECTION_PROGRESS_INTRODUCTION_SENT

	Core.'ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONNECTED'	= ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONNECTED
	Core.'ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONFIRMED'	= ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONFIRMED
	Core.'ANNOUNCEMENT_ERROR_NOT_ENOUGH_INTERMEDIATE_NODES'		= ANNOUNCEMENT_ERROR_NOT_ENOUGH_INTERMEDIATE_NODES
	Core:: =
		/**
		 * Start HTTP server listening on specified ip:port, so that current node will be capable of acting as bootstrap node for other users
		 *
		 * @param {string}	ip
		 * @param {number}	port
		 * @param {string}	address	Publicly available address that will be returned to other node, typically domain name (instead of using IP)
		 * @param {number}	public_port	Publicly available port on `address`
		 */
		'start_bootstrap_node' : (ip, port, address = ip, public_port = port) !->
			@_dht['start_bootstrap_node'](ip, port, address, public_port)
			@_bootstrap_node	= true
			# Stop doing any routing tasks immediately
			@_destroy_router()
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
			if @_bootstrap_node
				return null
			real_keypair	= create_keypair(real_key_seed)
			real_public_key	= real_keypair['ed25519']['public']
			# Ignore repeated announcement
			if @_real_keypairs.has(real_public_key)
				return null
			@_real_keypairs.set(
				real_public_key
				[real_keypair, number_of_introduction_nodes, number_of_intermediate_nodes, ArraySet()]
			)
			@_announce(real_public_key)
			real_public_key
		/**
		 * @param {!Uint8Array} real_public_key
		 */
		_announce : (real_public_key) !->
			[
				real_keypair
				number_of_introduction_nodes
				number_of_intermediate_nodes
				announced_to
			]								= @_real_keypairs.get(real_public_key)
			old_introduction_nodes			= []
			announced_to.forEach (introduction_node) !->
				old_introduction_nodes.push(introduction_node)
			number_of_introduction_nodes	= number_of_introduction_nodes - old_introduction_nodes.length
			if !number_of_introduction_nodes
				return
			@_update_last_announcement(real_public_key, +(new Date))
			introduction_nodes				= @_pick_random_aware_of_nodes(number_of_introduction_nodes, old_introduction_nodes)
			if !introduction_nodes
				@_update_last_announcement(real_public_key, 1)
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
					@_update_last_announcement(real_public_key, 1)
					@'fire'('announcement_failed', real_public_key, ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONFIRMED)
					return
				# Add old introduction nodes to the list
				introduction_nodes_confirmed	:= introduction_nodes_confirmed.concat(old_introduction_nodes)
				announcement_message			= @_generate_announcement_message(
					real_public_key
					real_keypair['ed25519']['private']
					introduction_nodes_confirmed
				)
				for introduction_node in introduction_nodes_confirmed
					@_send_to_routing_node(real_public_key, introduction_node, ROUTING_COMMAND_ANNOUNCE, announcement_message)
				# TODO: Check using independent routing path that announcement indeed happened
				@'fire'('announced', real_public_key)
			for let introduction_node in introduction_nodes
				nodes	= @_pick_nodes_for_routing_path(number_of_intermediate_nodes, introduction_nodes.concat(old_introduction_nodes))
				if !nodes
					@'fire'('announcement_failed', real_public_key, ANNOUNCEMENT_ERROR_NOT_ENOUGH_INTERMEDIATE_NODES)
					return
				nodes.push(introduction_node)
				first_node	= nodes[0]
				@_construct_routing_path(nodes)
					.then (route_id) !~>
						@_register_routing_path(real_public_key, introduction_node, first_node, route_id)
						announced_to.add(introduction_node)
						announced(introduction_node)
					.catch (error) !~>
						error_handler(error)
						announced()
		/**
		 * @param {!Uint8Array}	real_public_key
		 * @param {number}		value
		 */
		_update_last_announcement : (real_public_key, value) !->
			@_real_keypairs.get(real_public_key)[4]	= value
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
			if @_bootstrap_node
				return null
			if !number_of_intermediate_nodes
				throw new Error('Direct connections are not yet supported')
				# TODO: Support direct connections here?
			real_keypair	= create_keypair(real_key_seed)
			real_public_key	= real_keypair['ed25519']['public']
			# Don't connect to itself
			if are_arrays_equal(real_public_key, target_id)
				return null
			full_target_id	= concat_arrays([real_public_key, target_id])
			# Don't initiate 2 concurrent connections to the same node, it will not end up well
			if @_connections_in_progress.has(full_target_id)
				return real_public_key
			# `discarded` is used when alternative connection from a friend is happening at the same time and this connection establishing is discarded
			connection_in_progress	=
				initiator	: true
				discarded	: false
			@_connections_in_progress.set(full_target_id, connection_in_progress)
			if @_id_to_routing_path.has(full_target_id)
				# Already connected, do nothing
				return null
			!~function connection_failed (code)
				if connection_in_progress.discarded
					return
				@_connections_in_progress.delete(full_target_id)
				# A bit ugly, but in this case routing path construction may succeed, while eventual connection to the target node fails
				if first_node
					@_used_first_nodes.delete(first_node)
				@'fire'('connection_failed', real_public_key, target_id, code)
			nodes	= @_pick_nodes_for_routing_path(number_of_intermediate_nodes)
			if !nodes
				connection_failed(CONNECTION_ERROR_NOT_ENOUGH_INTERMEDIATE_NODES)
				return null
			first_node		= nodes[0]
			rendezvous_node	= nodes[* - 1]
			@_construct_routing_path(nodes)
				.then (route_id) !~>
					@'fire'('connection_progress', real_public_key, target_id, CONNECTION_PROGRESS_CONNECTED_TO_RENDEZVOUS_NODE)
					!~function found_introduction_nodes (new_node_id, new_route_id, command, data)
						if !(
							are_arrays_equal(first_node, new_node_id) &&
							are_arrays_equal(route_id, new_route_id) &&
							command == ROUTING_COMMAND_FIND_INTRODUCTION_NODES_RESPONSE
						)
							return
						[code, introduction_target_id, introduction_nodes]	= parse_find_introduction_nodes_response(data)
						if !are_arrays_equal(target_id, introduction_target_id)
							return
						clearTimeout(find_introduction_nodes_timeout)
						if code != CONNECTION_OK
							connection_failed(code)
							return
						@'fire'('connection_progress', real_public_key, target_id, CONNECTION_PROGRESS_FOUND_INTRODUCTION_NODES)
						!~function try_to_introduce
							if connection_in_progress.discarded
								return
							if !introduction_nodes.length
								connection_failed(CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES)
								return
							introduction_node				= pull_random_item_from_array(introduction_nodes)
							rendezvous_token				= random_bytes(ID_LENGTH)
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
							!~function path_confirmation (new_node_id, new_route_id, command, data)
								if !(
									are_arrays_equal(first_node, new_node_id) &&
									are_arrays_equal(route_id, new_route_id) &&
									command == ROUTING_COMMAND_CONNECTED
								)
									return
								[signature, rendezvous_token_received, handshake_message_received]	= parse_confirm_connection_data(data)
								if !(
									are_arrays_equal(rendezvous_token_received, rendezvous_token) &&
									detox-crypto['verify'](signature, rendezvous_token, target_id)
								)
									return
								encryptor_instance['put_handshake_message'](handshake_message_received)
								@_encryptor_instances.set(full_target_id, encryptor_instance)
								clearTimeout(path_confirmation_timeout)
								@_router['off']('data', path_confirmation)
								@_register_routing_path(real_public_key, target_id, first_node, route_id)
								@_connections_in_progress.delete(full_target_id)
								@_register_application_connection(real_public_key, target_id)
							@_router['on']('data', path_confirmation)
							@_send_to_routing_node_raw(
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
					@_send_to_routing_node_raw(first_node, route_id, ROUTING_COMMAND_FIND_INTRODUCTION_NODES_REQUEST, target_id)
					find_introduction_nodes_timeout	= timeoutSet(CONNECTION_TIMEOUT, !~>
						@_router['off']('data', found_introduction_nodes)
						connection_failed(CONNECTION_ERROR_CANT_FIND_INTRODUCTION_NODES)
					)
				.catch (error) !~>
					error_handler(error)
					connection_failed(CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_NODE)
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
			if @_bootstrap_node
				return
			full_target_id		= concat_arrays([real_public_key, target_id])
			encryptor_instance	= @_encryptor_instances.get(full_target_id)
			if !encryptor_instance || data.length > @_max_data_size
				return
			multiplexer			= @_multiplexers.get(full_target_id)
			if !multiplexer
				return
			data_with_header	= new Uint8Array(data.length + 1)
				..set([command])
				..set(data, 1)
			multiplexer['feed'](data_with_header)
			if @_pending_sending.has(full_target_id)
				# Timer is already in progress
				return
			# It might sometimes happen that we send command with small piece of data and the rest of the block is wasted. Sending data after 0 timeout
			# allows for a few synchronous `send_to` calls to share the same block if possible in order to use space more efficiently
			@_pending_sending.set(
				full_target_id
				setTimeout !~>
					@_pending_sending.delete(full_target_id)
					while multiplexer['have_more_blocks']()
						data_block				= multiplexer['get_block']()
						data_block_encrypted	= encryptor_instance['encrypt'](data_block)
						@_send_to_routing_node(real_public_key, target_id, ROUTING_COMMAND_DATA, data_block_encrypted)
			)
		'destroy' : !->
			if @_destroyed
				return
			# Bootstrap node immediately destroys router, no need to do it again
			if !@_bootstrap_node
				@_destroy_router()
			@_dht['destroy']()
			@_destroyed	= true
		_destroy_router : !->
			clearInterval(@_cleanup_interval)
			clearInterval(@_keep_announce_routes_interval)
			clearInterval(@_get_more_nodes_interval)
			# Delete all tags and only rely on DHT's needs for existing connections
			@_connections_timeouts.forEach (, node_id) !~>
				@_del_used_tag(node_id)
			@_routing_paths.forEach ([node_id, route_id]) !~>
				@_unregister_routing_path(node_id, route_id)
			@_pending_connection.forEach ([, , , connection_timeout]) !~>
				clearTimeout(connection_timeout)
			@_router['destroy']()
		/**
		 * @return {boolean}
		 */
		_more_aware_of_nodes_needed : ->
			!@_bootstrap_node && !!(@_aware_of_nodes.size < AWARE_OF_NODES_LIMIT || @_get_stale_aware_of_nodes(true).length)
		/**
		 * @param {boolean=} early_exit Will return single node if present, used to check if stale nodes are present at all
		 *
		 * @return {!Array<string>}
		 */
		_get_stale_aware_of_nodes : (early_exit = false) ->
			stale_aware_of_nodes	= []
			stale_older_than		= +(new Date) - STALE_AWARE_OF_NODE_TIMEOUT * 1000
			exited					= false
			@_aware_of_nodes.forEach (date, node_id) !->
				if !exited && date < stale_older_than
					stale_aware_of_nodes.push(node_id)
					if early_exit && !exited
						exited	:= true
			stale_aware_of_nodes
		/**
		 * Request more nodes to be aware of from some of the nodes already connected to
		 */
		_get_more_aware_of_nodes : !->
			nodes	= @_pick_random_connected_nodes(5)
			if !nodes
				return
			for node_id in nodes
				@_get_more_nodes_from(node_id)
		/**
		 * @param {!Uint8Array} node_id
		 */
		_get_more_nodes_from : (node_id) !->
			@_get_nodes_requested.add(node_id)
			@_send_to_dht_node(node_id, DHT_COMMAND_GET_NODES_REQUEST, new Uint8Array(0))
		/**
		 * Get some random nodes suitable for constructing routing path through them or for acting as introduction nodes
		 *
		 * @param {number}					number_of_nodes
		 * @param {!Array<!Uint8Array>=}	exclude_nodes
		 *
		 * @return {Array<!Uint8Array>} `null` if there was not enough nodes
		 */
		_pick_nodes_for_routing_path : (number_of_nodes, exclude_nodes = []) ->
			exclude_nodes	= Array.from(@_used_first_nodes.values()).concat(exclude_nodes)
			connected_node	= @_pick_random_connected_nodes(1, exclude_nodes)?[0]
			if !connected_node
				return null
			intermediate_nodes	= @_pick_random_aware_of_nodes(number_of_nodes - 1, exclude_nodes.concat([connected_node]))
			if !intermediate_nodes
				return null
			[connected_node].concat(intermediate_nodes)
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
				@_random_lookup()
				return null
			connected_nodes	= Array.from(@_connected_nodes.values())
			for bootstrap_node in @'get_bootstrap_nodes'()
				exclude_nodes.push(hex2array(bootstrap_node['node_id']))
			exclude_nodes_set	= ArraySet(exclude_nodes)
			connected_nodes		= connected_nodes.filter (node) ->
				!exclude_nodes_set.has(node)
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
			aware_of_nodes	= Array.from(@_aware_of_nodes.keys())
			if exclude_nodes
				exclude_nodes_set	= ArraySet(exclude_nodes)
				aware_of_nodes		= aware_of_nodes.filter (node) ->
					!exclude_nodes_set.has(node)
			if aware_of_nodes.length < number_of_nodes
				return null
			for i from 0 til number_of_nodes
				pull_random_item_from_array(aware_of_nodes)
		_random_lookup : !->
			@_dht['lookup'](fake_node_id())
		/**
		 * @param {!Array<!Uint8Array>} nodes
		 *
		 * @return {!Promise}
		 */
		_construct_routing_path : (nodes) ->
			first_node	= nodes[0]
			# Store first node as used, so that we don't use it for building other routing paths
			@_used_first_nodes.add(first_node)
			@_router['construct_routing_path'](nodes)
				..catch !->
					@_used_first_nodes.delete(first_node)
		/**
		 * @param {!Uint8Array} real_public_key
		 * @param {!Uint8Array} target_id		Last node in routing path, responder
		 * @param {!Uint8Array} node_id			First node in routing path, used for routing path identification
		 * @param {!Uint8Array} route_id		ID of the route on `node_id`
		 */
		_register_routing_path : (real_public_key, target_id, node_id, route_id) !->
			source_id	= concat_arrays([node_id, route_id])
			if @_routing_path_to_id.has(source_id)
				# Something went wrong, ignore
				return
			full_target_id	= concat_arrays([real_public_key, target_id])
			@_id_to_routing_path.set(full_target_id, [node_id, route_id])
			@_routing_path_to_id.set(source_id, [real_public_key, target_id])
			# Make sure each chunk after encryption will fit perfectly into DHT packet
			# Multiplexer/demultiplexer pair is not needed for introduction node, but for simplicity we'll create it anyway
			@_multiplexers.set(full_target_id, fixed-size-multiplexer['Multiplexer'](@_max_data_size, @_max_packet_data_size))
			@_demultiplexers.set(full_target_id, fixed-size-multiplexer['Demultiplexer'](@_max_data_size, @_max_packet_data_size))
			@'fire'('routing_paths_count', @_id_to_routing_path.size)
		/**
		 * @param {!Uint8Array} node_id		First node in routing path, used for routing path identification
		 * @param {!Uint8Array} route_id	ID of the route on `node_id`
		 */
		_unregister_routing_path : (node_id, route_id) !->
			source_id	= concat_arrays([node_id, route_id])
			if !@_routing_paths.has(source_id)
				return
			@_used_first_nodes.delete(node_id)
			@_routing_paths.delete(source_id)
			@_router['destroy_routing_path'](node_id, route_id)
			@_pending_pings.delete(source_id)
			@_announcements_from.forEach ([node_id, route_id, announce_interval], target_id) !~>
				source_id_local	= concat_arrays([node_id, route_id])
				if !are_arrays_equal(source_id, source_id_local)
					return
				clearInterval(announce_interval)
				@_announcements_from.delete(target_id)
			if !@_routing_path_to_id.has(source_id)
				return
			[real_public_key, target_id]	= @_routing_path_to_id.get(source_id)
			full_target_id					= concat_arrays([real_public_key, target_id])
			@_routing_path_to_id.delete(source_id)
			@_id_to_routing_path.delete(full_target_id)
			if @_pending_sending.has(full_target_id)
				clearTimeout(@_pending_sending.get(full_target_id))
				@_pending_sending.delete(full_target_id)
			if @_real_keypairs.has(real_public_key)
				announced_to	= @_real_keypairs.get(real_public_key)[3]
				announced_to.delete(target_id)
			encryptor_instance	= @_encryptor_instances.get(full_target_id)
			if encryptor_instance
				encryptor_instance['destroy']()
				@_encryptor_instances.delete(full_target_id)
			@_multiplexers.delete(full_target_id)
			@_demultiplexers.delete(full_target_id)
			@_unregister_application_connection(real_public_key, target_id)
			@'fire'('routing_paths_count', @_id_to_routing_path.size)
		/**
		 * @param {!Uint8Array} real_public_key
		 * @param {!Uint8Array} target_id		Last node in routing path, responder
		 */
		_register_application_connection : (real_public_key, target_id) !->
			full_target_id	= concat_arrays([real_public_key, target_id])
			@_application_connections.add(full_target_id)
			@'fire'('connected', real_public_key, target_id)
			@'fire'('application_connections_count', @_application_connections.size)
		/**
		 * @param {!Uint8Array} real_public_key
		 * @param {!Uint8Array} target_id		Last node in routing path, responder
		 */
		_unregister_application_connection : (real_public_key, target_id) !->
			full_target_id	= concat_arrays([real_public_key, target_id])
			if @_application_connections.has(full_target_id)
				@_application_connections.delete(full_target_id)
				@'fire'('disconnected', real_public_key, target_id)
				@'fire'('application_connections_count', @_application_connections.size)
		/**
		 * @param {!Uint8Array}	node_id
		 * @param {number}		command	0..245
		 * @param {!Uint8Array}	data
		 */
		_send_to_dht_node : (node_id, command, data) !->
			if @_connected_nodes.has(node_id)
				@_update_connection_timeout(node_id)
				@_dht['send_data'](node_id, command, data)
				return
			!~function connected (new_node_id)
				if !are_arrays_equal(node_id, new_node_id)
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
			full_target_id	= concat_arrays([real_public_key, target_id])
			if !@_id_to_routing_path.has(full_target_id)
				return
			[node_id, route_id] = @_id_to_routing_path.get(full_target_id)
			@_send_to_routing_node_raw(node_id, route_id, command, data)
		/**
		 * @param {!Uint8Array} node_id
		 * @param {!Uint8Array} route_id
		 * @param {number}		command
		 * @param {!Uint8Array}	data
		 */
		_send_to_routing_node_raw : (node_id, route_id, command, data) ->
			if data.length == 0
				# Just to make sure demultiplexer will not discard this command
				data	= new Uint8Array(1)
			@_router['send_data'](node_id, route_id, command, data)
		/**
		 * @param {!Uint8Array} node_id
		 * @param {!Uint8Array} route_id
		 *
		 * @return {boolean} `true` if ping was sent (not necessary delivered)
		 */
		_send_ping : (node_id, route_id) ->
			source_id	= concat_arrays([node_id, route_id])
			if @_pending_pings.has(source_id) || !@_routing_paths.has(source_id)
				return false
			@_send_to_routing_node_raw(node_id, route_id, ROUTING_COMMAND_PING, new Uint8Array(0))
			true
		/**
		 * @param {!Uint8Array} node_id
		 */
		_update_connection_timeout : (node_id) !->
			if !@_connections_timeouts.has(node_id)
				@_add_used_tag(node_id)
			@_connections_timeouts.set(node_id, +(new Date))
		/**
		 * @param {!Uint8Array} node_id
		 */
		_add_used_tag : (node_id) !->
			value = @_used_tags.get(node_id) || 0
			++value
			@_used_tags.set(node_id, value)
			if value == 1
				@_dht['add_used_tag'](node_id)
		/**
		 * @param {!Uint8Array} node_id
		 */
		_del_used_tag : (node_id) !->
			value = @_used_tags.get(node_id)
			if !value
				return
			--value
			if !value
				@_used_tags.delete(node_id)
				@_dht['del_used_tag'](node_id)
			else
				@_used_tags.set(node_id, value)
		/**
		 * Generate message with introduction nodes that can later be published by any node connected to DHT (typically other node than this for anonymity)
		 *
		 * @param {!Uint8Array}			real_public_key		Ed25519 public key (real one, different from supplied in DHT constructor)
		 * @param {!Uint8Array}			real_private_key	Corresponding Ed25519 private key
		 * @param {!Array<!Uint8Array>}	introduction_nodes	Array of public keys of introduction points
		 *
		 * @return {!Uint8Array}
		 */
		_generate_announcement_message : (real_public_key, real_private_key, introduction_nodes) ->
			time	= parseInt(+(new Date) / 1000) # In seconds, should be enough if kept as unsigned 32-bit integer which we actually do
			concat_arrays(@_dht['make_mutable_value'](real_public_key, real_private_key, time, concat_arrays(introduction_nodes)))
		/**
		 * @param {!Uint8Array} message
		 *
		 * @return {Uint8Array} Public key if signature is correct, `null` otherwise
		 */
		_verify_announcement_message : (message) ->
			real_public_key	= message.subarray(0, PUBLIC_KEY_LENGTH)
			data			= message.subarray(PUBLIC_KEY_LENGTH)
			payload			= @_dht['verify_value'](real_public_key, data)
			# If value is not valid or length doesn't fit certain number of introduction nodes exactly
			if !payload || (payload[1].length % PUBLIC_KEY_LENGTH)
				null
			else
				real_public_key
		/**
		 * Publish message with introduction nodes (typically happens on different node than `_generate_announcement_message()`)
		 *
		 * @param {!Uint8Array} message
		 */
		_publish_announcement_message : (message) !->
			if @_destroyed
				return
			real_public_key	= message.subarray(0, PUBLIC_KEY_LENGTH)
			data			= message.subarray(PUBLIC_KEY_LENGTH)
			@_dht['put_value'](real_public_key, data)
		/**
		 * Find nodes in DHT that are acting as introduction points for specified public key
		 *
		 * @param {!Uint8Array}	target_public_key
		 *
		 * @return {!Promise} Resolves with `!Array<!Uint8Array>`
		 */
		_find_introduction_nodes : (target_public_key) ->
			if @_destroyed
				return Promise.reject()
			@_dht['get_value'](target_public_key).then (introduction_nodes_bulk) ->
				if introduction_nodes_bulk.length % PUBLIC_KEY_LENGTH != 0
					throw ''
				introduction_nodes	= []
				for i from 0 til introduction_nodes_bulk.length / PUBLIC_KEY_LENGTH
					introduction_nodes.push(introduction_nodes_bulk.subarray(i * PUBLIC_KEY_LENGTH, (i + 1) * PUBLIC_KEY_LENGTH))
				introduction_nodes

	Core:: = Object.assign(Object.create(async-eventer::), Core::)
	Object.defineProperty(Core::, 'constructor', {value: Core})
	{
		'ready'			: (callback) !->
			<-! detox-crypto['ready']
			<-! detox-transport['ready']
			callback()
		/**
		 * Generate random seed that can be used as keypair seed
		 *
		 * @return {!Uint8Array} 32 bytes
		 */
		'generate_seed'	: ->
			random_bytes(ID_LENGTH)
		'Core'			: Core
	}

if typeof define == 'function' && define['amd']
	# AMD
	define(['@detox/crypto', '@detox/transport', '@detox/utils', 'fixed-size-multiplexer', 'async-eventer'], Wrapper)
else if typeof exports == 'object'
	# CommonJS
	module.exports = Wrapper(require('@detox/crypto'), require('@detox/transport'), require('@detox/utils'), require('fixed-size-multiplexer'), require('async-eventer'))
else
	# Browser globals
	@'detox_core' = Wrapper(@'detox_crypto', @'detox_transport', @'detox_utils', @'fixed_size_multiplexer', @'async_eventer')
