/**
 * @package Detox core
 * @author  Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @license 0BSD
 */
/*
 * Implements version ? of the specification
 */
const DHT_COMMANDS_OFFSET				= 10				# 0..9 are reserved as Core commands
const ROUTING_COMMANDS					= 20				# 10..19 are reserved as DHT commands
const UNCOMPRESSED_COMMANDS_OFFSET		= ROUTING_COMMANDS	# Core and DHT commands are compressed
const UNCOMPRESSED_CORE_COMMANDS_OFFSET	= 21

const COMPRESSED_CORE_COMMAND_SIGNAL	= 0

const UNCOMPRESSED_CORE_COMMAND_FORWARD_INTRODUCTION	= 0
const UNCOMPRESSED_CORE_COMMAND_GET_NODES_REQUEST		= 1
const UNCOMPRESSED_CORE_COMMAND_GET_NODES_RESPONSE		= 2
const UNCOMPRESSED_CORE_COMMAND_BOOTSTRAP_NODE			= 3

const ROUTING_COMMAND_ANNOUNCE							= 0
const ROUTING_COMMAND_FIND_INTRODUCTION_NODES_REQUEST	= 1
const ROUTING_COMMAND_FIND_INTRODUCTION_NODES_RESPONSE	= 2
const ROUTING_COMMAND_INITIALIZE_CONNECTION				= 3
const ROUTING_COMMAND_INTRODUCTION						= 4
const ROUTING_COMMAND_CONFIRM_CONNECTION				= 5
const ROUTING_COMMAND_CONNECTED							= 6
const ROUTING_COMMAND_DATA								= 7
const ROUTING_COMMAND_PING								= 8

const PUBLIC_KEY_LENGTH			= 32
const SIGNATURE_LENGTH			= 64
# Handshake message length for Noise_NK_25519_ChaChaPoly_BLAKE2b
const HANDSHAKE_MESSAGE_LENGTH	= 48
# ChaChaPoly+BLAKE2b
const MAC_LENGTH				= 16
# Length of the application name used during introduction
const APPLICATION_LENGTH		= 64
const DEFAULT_TIMEOUTS			=
	# How long node should wait for rendezvous node to receive incoming connection from intended responder
	'CONNECTION_TIMEOUT'				: 10
	# After specified number of seconds since last data sending or receiving connection or route is considered unused and can be closed
	'LAST_USED_TIMEOUT'					: 60
	# Re-announce each 5 minutes
	'ANNOUNCE_INTERVAL'					: 10 * 60
	# After 5 minutes aware of node is considered stale and needs refreshing or replacing with a new one
	'STALE_AWARE_OF_NODE_TIMEOUT'		: 5 * 60
	# New aware of nodes will be fetched and old refreshed each 30 seconds
	'GET_MORE_AWARE_OF_NODES_INTERVAL'	: 30
	# Max time in seconds allowed for routing path segment creation after which creation is considered failed
	'ROUTING_PATH_SEGMENT_TIMEOUT'		: 10

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
 * @param {!Uint8Array} source_id
 * @param {!Uint8Array} target_id
 * @param {!Uint8Array} sdp
 * @param {!Uint8Array} signature
 *
 * @return {!Uint8Array}
 */
function compose_signal (source_id, target_id, sdp, signature)
	new Uint8Array(PUBLIC_KEY_LENGTH * 2 + sdp.length + SIGNATURE_LENGTH)
		..set(source_id)
		..set(target_id, PUBLIC_KEY_LENGTH)
		..set(sdp, PUBLIC_KEY_LENGTH * 2)
		..set(signature, PUBLIC_KEY_LENGTH * 2 + sdp.length)
/**
 * @param {!Uint8Array} data
 *
 * @return {!Array} [source_id, target_id, sdp, signature]
 */
function parse_signal (data)
	source_id	= data.subarray(0, PUBLIC_KEY_LENGTH)
	target_id	= data.subarray(PUBLIC_KEY_LENGTH, PUBLIC_KEY_LENGTH * 2)
	sdp			= data.subarray(PUBLIC_KEY_LENGTH * 2, data.length - SIGNATURE_LENGTH)
	signature	= data.subarray(data.length - SIGNATURE_LENGTH)
	[source_id, target_id, sdp, signature]
/**
 * @param {number}				code
 * @param {!Uint8Array}			target_id
 * @param {!Array<!Uint8Array>}	nodes
 *
 * @return {!Uint8Array}
 */
function compose_find_introduction_nodes_response (code, target_id, nodes)
	result	= new Uint8Array(1 + PUBLIC_KEY_LENGTH + nodes.length * PUBLIC_KEY_LENGTH)
		..set([code])
		..set(target_id, 1)
	for node, i in nodes
		result.set(node, 1 + PUBLIC_KEY_LENGTH + i * PUBLIC_KEY_LENGTH)
	result
/**
 * @param {!Uint8Array} data
 *
 * @return {!Array} [code, target_id, nodes]
 */
function parse_find_introduction_nodes_response (data)
	code		= data[0]
	target_id	= data.subarray(1, 1 + PUBLIC_KEY_LENGTH)
	nodes		= []
	data		= data.subarray(1 + PUBLIC_KEY_LENGTH)
	for i from 0 til data.length / PUBLIC_KEY_LENGTH
		nodes.push(data.subarray(i * PUBLIC_KEY_LENGTH, (i + 1) * PUBLIC_KEY_LENGTH))
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
	new Uint8Array(PUBLIC_KEY_LENGTH * 3 + HANDSHAKE_MESSAGE_LENGTH + APPLICATION_LENGTH + PUBLIC_KEY_LENGTH)
		..set(target_id)
		..set(rendezvous_node, PUBLIC_KEY_LENGTH)
		..set(rendezvous_token, PUBLIC_KEY_LENGTH * 2)
		..set(handshake_message, PUBLIC_KEY_LENGTH * 3)
		..set(application, PUBLIC_KEY_LENGTH * 3 + HANDSHAKE_MESSAGE_LENGTH)
		..set(secret, PUBLIC_KEY_LENGTH * 3 + HANDSHAKE_MESSAGE_LENGTH + APPLICATION_LENGTH)
/**
 * @param {!Uint8Array} introduction_payload
 *
 * @return {!Array<!Uint8Array>} [target_id, rendezvous_node, rendezvous_token, handshake_message, application, secret]
 */
function parse_introduction_payload (introduction_payload)
	target_id			= introduction_payload.subarray(0, PUBLIC_KEY_LENGTH)
	rendezvous_node		= introduction_payload.subarray(PUBLIC_KEY_LENGTH, PUBLIC_KEY_LENGTH * 2)
	rendezvous_token	= introduction_payload.subarray(PUBLIC_KEY_LENGTH * 2, PUBLIC_KEY_LENGTH * 3)
	handshake_message	= introduction_payload.subarray(PUBLIC_KEY_LENGTH * 3, PUBLIC_KEY_LENGTH * 3 + HANDSHAKE_MESSAGE_LENGTH)
	application			= introduction_payload.subarray(PUBLIC_KEY_LENGTH * 3 + HANDSHAKE_MESSAGE_LENGTH, PUBLIC_KEY_LENGTH * 3 + HANDSHAKE_MESSAGE_LENGTH + APPLICATION_LENGTH)
	secret				= introduction_payload.subarray(PUBLIC_KEY_LENGTH * 3 + HANDSHAKE_MESSAGE_LENGTH + APPLICATION_LENGTH, PUBLIC_KEY_LENGTH * 3 + HANDSHAKE_MESSAGE_LENGTH + APPLICATION_LENGTH + PUBLIC_KEY_LENGTH)
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
	new Uint8Array(PUBLIC_KEY_LENGTH * 3 + introduction_message.length)
		..set(rendezvous_token)
		..set(introduction_node, PUBLIC_KEY_LENGTH)
		..set(target_id, PUBLIC_KEY_LENGTH * 2)
		..set(introduction_message, PUBLIC_KEY_LENGTH * 3)
/**
 * @param {!Uint8Array} message
 *
 * @return {!Array<!Uint8Array>} [rendezvous_token, introduction_node, target_id, introduction_message]
 */
function parse_initialize_connection_data (message)
	rendezvous_token		= message.subarray(0, PUBLIC_KEY_LENGTH)
	introduction_node		= message.subarray(PUBLIC_KEY_LENGTH, PUBLIC_KEY_LENGTH * 2)
	target_id				= message.subarray(PUBLIC_KEY_LENGTH * 2, PUBLIC_KEY_LENGTH * 3)
	introduction_message	= message.subarray(PUBLIC_KEY_LENGTH * 3)
	[rendezvous_token, introduction_node, target_id, introduction_message]
/**
 * @param {!Uint8Array} signature
 * @param {!Uint8Array} rendezvous_token
 * @param {!Uint8Array} handshake_message
 *
 * @return {!Uint8Array}
 */
function compose_confirm_connection_data (signature, rendezvous_token, handshake_message)
	new Uint8Array(SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH + HANDSHAKE_MESSAGE_LENGTH)
		..set(signature)
		..set(rendezvous_token, SIGNATURE_LENGTH)
		..set(handshake_message, SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH)
/**
 * @param {!Uint8Array} message
 *
 * @return {!Array<!Uint8Array>} [signature, rendezvous_token, handshake_message]
 */
function parse_confirm_connection_data (message)
	signature			= message.subarray(0, SIGNATURE_LENGTH)
	rendezvous_token	= message.subarray(SIGNATURE_LENGTH, SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH)
	handshake_message	= message.subarray(SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH)
	[signature, rendezvous_token, handshake_message]
/**
 * @param {!Uint8Array} target_id
 * @param {!Uint8Array} introduction_message
 *
 * @return {!Uint8Array}
 */
function compose_introduce_to_data (target_id, introduction_message)
	new Uint8Array(PUBLIC_KEY_LENGTH + introduction_message.length)
		..set(target_id)
		..set(introduction_message, PUBLIC_KEY_LENGTH)
/**
 * @param {!Uint8Array} message
 *
 * @return {!Array<!Uint8Array>} [target_id, introduction_message]
 */
function parse_introduce_to_data (message)
	target_id				= message.subarray(0, PUBLIC_KEY_LENGTH)
	introduction_message	= message.subarray(PUBLIC_KEY_LENGTH)
	[target_id, introduction_message]

/**
 * @param {!Function=} fetch
 */
function Wrapper (detox-crypto, detox-dht, detox-routing, detox-transport, detox-utils, fixed-size-multiplexer, async-eventer, fetch = window['fetch'])
	string2array				= detox-utils['string2array']
	array2string				= detox-utils['array2string']
	random_bytes				= detox-utils['random_bytes']
	random_int					= detox-utils['random_int']
	pull_random_item_from_array	= detox-utils['pull_random_item_from_array']
	are_arrays_equal			= detox-utils['are_arrays_equal']
	concat_arrays				= detox-utils['concat_arrays']
	timeoutSet					= detox-utils['timeoutSet']
	intervalSet					= detox-utils['intervalSet']
	error_handler				= detox-utils['error_handler']
	ArrayMap					= detox-utils['ArrayMap']
	ArraySet					= detox-utils['ArraySet']
	empty_array					= new Uint8Array(0)
	null_id						= new Uint8Array(PUBLIC_KEY_LENGTH)
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
	 * @param {!Array<string>}	bootstrap_nodes			Array of strings in format `address:port`
	 * @param {!Array<!Object>}	ice_servers
	 * @param {number}			packets_per_second		Each packet send in each direction has exactly the same size and packets are sent at fixed rate (>= 1)
	 * @param {number}			bucket_size
	 * @param {Object=}			options					More options that are less frequently used
	 *
	 * @return {!Core}
	 *
	 * @throws {Error}
	 */
	!function Core (dht_key_seed, bootstrap_nodes, ice_servers, packets_per_second = 1, bucket_size = 2, options = {})
		if !(@ instanceof Core)
			return new Core(dht_key_seed, bootstrap_nodes, ice_servers, packets_per_second, bucket_size, options)
		async-eventer.call(@)

		@_options	= Object.assign(
			{
				'state_history_size'				: 1000
				'values_cache_size'					: 1000
				'fraction_of_nodes_from_same_peer'	: 0.2
				'lookup_number'						: Math.max(bucket_size, 5)
				'max_pending_segments'				: 10
				'aware_of_nodes_limit'				: 1000
				'min_number_of_peers_for_ready'		: bucket_size # TODO: Use this option
				'connected_nodes_limit'				: 100
			}
			options
			{
				'timeouts'	: Object.assign({}, DEFAULT_TIMEOUTS, options['timeouts'] || {})
			}
		)

		@_real_keypairs				= ArrayMap()
		@_dht_keypair				= create_keypair(dht_key_seed)
		@_max_data_size				= detox-transport['MAX_DATA_SIZE']
		@_max_compressed_data_size	= detox-transport['MAX_COMPRESSED_DATA_SIZE']

		@_bootstrap_nodes			= new Set(bootstrap_nodes)
		@_bootstrap_nodes_ids		= ArraySet()
		@_used_first_nodes			= ArraySet()
		@_connections_in_progress	= ArrayMap()
		@_connected_nodes			= ArraySet()
		@_waiting_for_signal		= ArrayMap()
		@_aware_of_nodes			= ArrayMap()
		@_get_nodes_requested		= ArraySet()
		@_routing_paths				= ArrayMap()
		# Mapping from responder ID to routing path and from routing path to responder ID, so that we can use responder ID for external API
		@_id_to_routing_path		= ArrayMap()
		@_routing_path_to_id		= ArrayMap()
		@_connections_timeouts		= ArrayMap()
		@_routes_timeouts			= ArrayMap()
		@_pending_connections		= ArrayMap()
		@_announcements_from		= ArrayMap()
		@_forwarding_mapping		= ArrayMap()
		@_pending_pings				= ArraySet()
		@_encryptor_instances		= ArrayMap()
		@_multiplexers				= ArrayMap()
		@_demultiplexers			= ArrayMap()
		@_pending_sending			= ArrayMap()
		@_application_connections	= ArraySet()

		@_cleanup_interval				= intervalSet(@_options['timeouts']['LAST_USED_TIMEOUT'], !~>
			# Unregister unused routing paths
			unused_older_than	= +(new Date) - @_options['timeouts']['LAST_USED_TIMEOUT'] * 1000
			@_routes_timeouts.forEach (last_updated, source_id) !~>
				if last_updated < unused_older_than
					if @_routing_paths.has(source_id)
						[node_id, route_id]	= @_routing_paths.get(source_id)
						@_unregister_routing_path(node_id, route_id)
					@_routes_timeouts.delete(source_id)
			# Un-tag connections that are no longer used
			@_connections_timeouts.forEach (last_updated, node_id) !~>
				if last_updated < unused_older_than
					@_connections_timeouts.delete(node_id)
					@_transport['destroy_connection'](node_id)
			# Remove aware of nodes that are stale for more that double of regular timeout
			super_stale_older_than	= +(new Date) - @_options['timeouts']['STALE_AWARE_OF_NODE_TIMEOUT'] * 2 * 1000
			@_aware_of_nodes.forEach (date, node_id) !~>
				if date < super_stale_older_than
					@_aware_of_nodes.delete(node_id)
		)
		# On 4/5 of the way to dropping connection
		@_keep_announce_routes_interval	= intervalSet(@_options['timeouts']['LAST_USED_TIMEOUT'] / 5 * 4, !~>
			@_real_keypairs.forEach ([real_keypair, number_of_introduction_nodes, number_of_intermediate_nodes, announced_to, last_announcement], real_public_key) !~>
				if announced_to.size < number_of_introduction_nodes && last_announcement
					# Give at least 3x time for announcement process to complete and to announce to some node
					reannounce_if_older_than	= +(new Date) - @_options['timeouts']['CONNECTION_TIMEOUT'] * 3
					if last_announcement < reannounce_if_older_than
						@_announce(real_public_key)
				announced_to.forEach (introduction_node) !~>
					full_introduction_node_id	= concat_arrays([real_public_key, introduction_node])
					[node_id, route_id]			= @_id_to_routing_path.get(full_introduction_node_id)
					if @_send_ping(node_id, route_id)
						source_id	= concat_arrays([node_id, route_id])
						@_pending_pings.add(source_id)
		)
		@_get_more_nodes_interval		= intervalSet(@_options['timeouts']['GET_MORE_AWARE_OF_NODES_INTERVAL'], !~>
			if @_more_aware_of_nodes_needed()
				@_get_more_aware_of_nodes()
		)

		@_transport	= detox-transport['Transport'](@_dht_keypair['ed25519']['public'], ice_servers, packets_per_second, UNCOMPRESSED_COMMANDS_OFFSET, @_options['timeouts']['CONNECTION_TIMEOUT'])
			.'on'('connected', (peer_id) !~>
				@_dht['add_peer'](peer_id)
				@_connected_nodes.add(peer_id)
				@_aware_of_nodes.delete(peer_id)
				@'fire'('aware_of_nodes_count', @_aware_of_nodes.size)
				@'fire'('connected_nodes_count', @_connected_nodes.size)
				if @_bootstrap_node
					@_send_uncompressed_core_command(peer_id, UNCOMPRESSED_CORE_COMMAND_BOOTSTRAP_NODE, string2array(@_http_server_address))
				if @_more_aware_of_nodes_needed()
					# TODO: Think about requesting aware of nodes from peers only
					@_get_more_nodes_from(peer_id)
				# TODO: Drop suspicious and less useful nodes first
				if @_connected_nodes.size > @_options['connected_nodes_limit']
					random_connected_node = @_pick_random_connected_nodes(1, [peer_id])[0]
					@_transport['destroy_connection'](peer_id)
			)
			.'on'('disconnected', (peer_id) !~>
				@_dht['del_peer'](peer_id)
				@_connected_nodes.delete(peer_id)
				@'fire'('connected_nodes_count', @_connected_nodes.size)
				@_get_nodes_requested.delete(peer_id)
			)
			.'on'('data', (peer_id, command, command_data) !~>
				if command >= UNCOMPRESSED_CORE_COMMANDS_OFFSET
					if @_bootstrap_node && command != UNCOMPRESSED_CORE_COMMAND_BOOTSTRAP_NODE
						return
					@_handle_uncompressed_core_command(peer_id, command - UNCOMPRESSED_CORE_COMMANDS_OFFSET, command_data)
				else if command == ROUTING_COMMANDS
					if @_bootstrap_node
						return
					@_router['process_packet'](peer_id, command_data)
				else if command >= DHT_COMMANDS_OFFSET
					@_dht['receive'](peer_id, command - DHT_COMMANDS_OFFSET, command_data)
				else
					if @_bootstrap_node && command != COMPRESSED_CORE_COMMAND_SIGNAL
						return
					@_handle_compressed_core_command(peer_id, command, command_data)
			)
		@_dht		= detox-dht['DHT'](
			@_dht_keypair['ed25519']['public']
			bucket_size
			@_options['state_history_size']
			@_options['values_cache_size']
			@_options['fraction_of_nodes_from_same_peer']
			@_options['timeouts']
		)
			.'on'('peer_error', (peer_id) !~>
				@_peer_error(peer_id)
			)
			.'on'('peer_warning', (peer_id) !~>
				@_peer_warning(peer_id)
			)
			.'on'('connect_to', (peer_peer_id, peer_id) ~>
				new Promise (resolve, reject) !~>
					if @_connected_nodes.has(peer_peer_id)
						resolve()
						return
					connection	= @_transport['get_connection'](peer_peer_id)
					if !connection
						connection	= @_transport['create_connection'](true, peer_peer_id)
						if !connection
							reject()
							return
						connection['on']('signal', (sdp) !~>
							signature		= detox-crypto['sign'](sdp, @_dht_keypair['ed25519']['public'], @_dht_keypair['ed25519']['private'])
							command_data	= compose_signal(@_dht_keypair['ed25519']['public'], peer_peer_id, sdp, signature)
							@_send_compressed_core_command(peer_id, COMPRESSED_CORE_COMMAND_SIGNAL, command_data)
						)
					connection
						.'once'('connected', !->
							connection['off']('disconnected', disconnected)
							resolve()
						)
						.'once'('disconnected', disconnected)
					!~function disconnected
						reject()
			)
			.'on'('send', (peer_id, command, command_data) !~>
				@_send_dht_command(peer_id, command, command_data)
			)
			.'on'('peer_updated', (peer_id, peer_peers) !~>
				# TODO: Store peer's peers for potential future deletion and add peer's peers to aware of nodes
			)
		@_router	= detox-routing['Router'](@_dht_keypair['x25519']['private'], @_options['max_pending_segments'], @_options['timeouts']['ROUTING_PATH_SEGMENT_TIMEOUT'])
			.'on'('activity', (node_id, route_id) !~>
				source_id	= concat_arrays([node_id, route_id])
				if !@_routing_paths.has(source_id)
					@_routing_paths.set(source_id, [node_id, route_id])
				@_routes_timeouts.set(source_id, +(new Date))
			)
			.'on'('send', (node_id, data) !~>
				@_send_routing_command(node_id, data)
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
						announce_interval	= intervalSet(@_options['timeouts']['ANNOUNCE_INTERVAL'], !~>
							if !@_routing_paths.has(source_id)
								return
							@_publish_announcement_message(data)
						)
						@_announcements_from.set(public_key, [node_id, route_id, announce_interval])
						@_publish_announcement_message(data)
					case ROUTING_COMMAND_FIND_INTRODUCTION_NODES_REQUEST
						target_id	= data
						if target_id.length != PUBLIC_KEY_LENGTH
							return
						/**
						 * @param {number}				code
						 * @param {!Array<!Uint8Array>}	nodes
						 */
						send_response	= (code, nodes) !~>
							data	= compose_find_introduction_nodes_response(code, target_id, nodes)
							@_send_to_routing_path(node_id, route_id, ROUTING_COMMAND_FIND_INTRODUCTION_NODES_RESPONSE, data)
						@_find_introduction_nodes(target_id)
							.then (introduction_nodes) !->
								if !introduction_nodes.length
									send_response(CONNECTION_ERROR_NO_INTRODUCTION_NODES, [])
								else
									send_response(CONNECTION_OK, introduction_nodes)
							.catch (error) !->
								error_handler(error)
								send_response(CONNECTION_ERROR_NO_INTRODUCTION_NODES, [])
					case ROUTING_COMMAND_INITIALIZE_CONNECTION
						[rendezvous_token, introduction_node, target_id, introduction_message]	= parse_initialize_connection_data(data)
						if @_pending_connections.has(rendezvous_token)
							# Ignore subsequent usages of the same rendezvous token
							return
						connection_timeout														= timeoutSet(@_options['timeouts']['CONNECTION_TIMEOUT'], !~>
							@_pending_connections.delete(rendezvous_token)
						)
						@_pending_connections.set(rendezvous_token, [node_id, route_id, target_id, connection_timeout])
						@_send_uncompressed_core_command(
							introduction_node
							UNCOMPRESSED_CORE_COMMAND_FORWARD_INTRODUCTION
							compose_introduce_to_data(target_id, introduction_message)
						)
					case ROUTING_COMMAND_CONFIRM_CONNECTION
						[signature, rendezvous_token, handshake_message]	= parse_confirm_connection_data(data)
						pending_connection									= @_pending_connections.get(rendezvous_token)
						if !pending_connection
							return
						[target_node_id, target_route_id, target_id, connection_timeout]	= pending_connection
						if !detox-crypto['verify'](signature, rendezvous_token, target_id)
							return
						@_pending_connections.delete(rendezvous_token)
						clearTimeout(connection_timeout)
						@_send_to_routing_path(target_node_id, target_route_id, ROUTING_COMMAND_CONNECTED, data)
						target_source_id	= concat_arrays([target_node_id, target_route_id])
						# TODO: There is no cleanup for these
						@_forwarding_mapping.set(source_id, [target_node_id, target_route_id])
						@_forwarding_mapping.set(target_source_id, [node_id, route_id])
					case ROUTING_COMMAND_INTRODUCTION
						routing_path_details	= @_routing_path_to_id.get(source_id)
						if !routing_path_details
							# If routing path unknown - ignore
							return
						[real_public_key, introduction_node]	= routing_path_details
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
							for_signature					= concat_arrays([introduction_node, introduction_payload])
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
							@_send_to_routing_path(target_node_id, target_route_id, ROUTING_COMMAND_DATA, data)
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
		# TODO: This should probably be called when a lot of nodes are disconnected too, not just once during start
		if !@_bootstrap_nodes.size
			setTimeout !~>
				@'fire'('ready')
		else
			@_bootstrap !~>
				# Make 3 random lookups on start in order to connect to some nodes
				# TODO: Think about regular lookups
				@_random_lookup().then ~>
					# TODO: Only fire when there are at least `@_bootstrap_nodes.size` connected nodes in total, otherwise it is not secure?
					@'fire'('ready')
	Core.'CONNECTION_ERROR_CANT_FIND_INTRODUCTION_NODES'		= CONNECTION_ERROR_CANT_FIND_INTRODUCTION_NODES
	Core.'CONNECTION_ERROR_NOT_ENOUGH_INTERMEDIATE_NODES'		= CONNECTION_ERROR_NOT_ENOUGH_INTERMEDIATE_NODES
	Core.'CONNECTION_ERROR_NO_INTRODUCTION_NODES'				= CONNECTION_ERROR_NO_INTRODUCTION_NODES
	Core.'CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_NODE'		= CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_NODE
	Core.'CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES'			= CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES

	Core.'CONNECTION_PROGRESS_CONNECTED_TO_RENDEZVOUS_NODE'		= CONNECTION_PROGRESS_CONNECTED_TO_RENDEZVOUS_NODE
	Core.'CONNECTION_PROGRESS_FOUND_INTRODUCTION_NODES'			= CONNECTION_PROGRESS_FOUND_INTRODUCTION_NODES
	Core.'CONNECTION_PROGRESS_INTRODUCTION_SENT'				= CONNECTION_PROGRESS_INTRODUCTION_SENT

	Core.'ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONNECTED'	= ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONNECTED
	Core.'ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONFIRMED'	= ANNOUNCEMENT_ERROR_NO_INTRODUCTION_NODES_CONFIRMED
	Core.'ANNOUNCEMENT_ERROR_NOT_ENOUGH_INTERMEDIATE_NODES'		= ANNOUNCEMENT_ERROR_NOT_ENOUGH_INTERMEDIATE_NODES
	Core:: =
		/**
		 * Start HTTP server listening on specified ip:port, so that current node will be capable of acting as bootstrap node for other users
		 *
		 * @param {string}	ip
		 * @param {number}	port
		 * @param {string}	public_address	Publicly available address that will be returned to other node, typically domain name (instead of using IP)
		 * @param {number}	public_port		Publicly available port on `address`
		 */
		'start_bootstrap_node' : (ip, port, public_address = ip, public_port = port) !->
			@_http_server = require('http')['createServer'] (request, response) !~>
				response['setHeader']('Access-Control-Allow-Origin', '*')
				content_length	= request.headers['content-length']
				if !(
					request.method == 'POST' &&
					content_length &&
					content_length <= @_max_compressed_data_size
				)
					response['writeHead'](400)
					response['end']()
					return
				body	= []
				request
					.'on'('data', (chunk) !->
						body.push(chunk)
					)
					.'on'('end', !~>
						body									:= concat_arrays(body)
						[source_id, target_id, sdp, signature]	= parse_signal(body)
						if !(
							detox-crypto['verify'](signature, sdp, source_id) &&
							are_arrays_equal(target_id, null_id)
						)
							response['writeHead'](400)
							response['end']()
							return
						if !@_connected_nodes.size || !random_int(0, @_connected_nodes.size)
							random_connected_node	= null
						else
							random_connected_node	= @_pick_random_connected_nodes(1)?[0]
						if random_connected_node
							waiting_for_signal_key	= concat_arrays([source_id, random_connected_node])
							if @_waiting_for_signal.has(waiting_for_signal_key)
								response['writeHead'](503)
								response['end']()
								return
							command_data	= compose_signal(source_id, random_connected_node, sdp, signature)
							@_send_compressed_core_command(random_connected_node, COMPRESSED_CORE_COMMAND_SIGNAL, command_data)
							@_waiting_for_signal.set(waiting_for_signal_key, (sdp, signature, command_data) !~>
								clearTimeout(timeout)
								if detox-crypto['verify'](signature, sdp, random_connected_node)
									response['write'](Buffer.from(command_data))
									response['end']()
								else
									response['writeHead'](502)
									response['end']()
							)
							timeout	= timeoutSet(@_options['timeouts']['CONNECTION_TIMEOUT'], !~>
								@_waiting_for_signal.delete(waiting_for_signal_key)
								response['writeHead'](504)
								response['end']()
							)
						else
							connection	= @_transport['create_connection'](false, source_id)
							if !connection
								response['writeHead'](503)
								response['end']()
								return
							connection
								.'once'('signal', (sdp) ~>
									signature	= detox-crypto['sign'](sdp, @_dht_keypair['ed25519']['public'], @_dht_keypair['ed25519']['private'])
									response['write'](Buffer.from(compose_signal(@_dht_keypair['ed25519']['public'], source_id, sdp, signature)))
									response['end']()
									false
								)
								.'signal'(sdp)
					)
			@_http_server
				.'on'('error', error_handler)
				.'listen'(port, ip, !~>
					@_http_server_address	= "#public_address:#public_port"
				)
			@_bootstrap_node	= true
			# Stop doing any routing tasks immediately
			@_destroy_router()
		/**
		 * Get an array of bootstrap nodes obtained during DHT operation in the same format as `bootstrap_nodes` argument in constructor
		 *
		 * @return {!Array<string>}
		 */
		'get_bootstrap_nodes' : ->
			Array.from(@_bootstrap_nodes)
		/**
		 * @param {Function=} callback
		 */
		_bootstrap : (callback) !->
			waiting_for	= @_bootstrap_nodes.size
			if !waiting_for
				callback?()
				return
			!~function done
				--waiting_for
				if waiting_for
					return
				pending_update	= timeoutSet(@_options['timeouts']['CONNECTION_TIMEOUT'], !~>
					@_bootstrap()
				)
				@_dht['once']('peer_updated', !~>
					clearTimeout(pending_update)
					callback?()
				)
			@_bootstrap_nodes.forEach (bootstrap_node) !~>
				random_id	= random_bytes(PUBLIC_KEY_LENGTH)
				connection	= @_transport['create_connection'](true, random_id)
				if !connection
					return
				connection
					.'on'('signal', (sdp) !~>
						signature	= detox-crypto['sign'](sdp, @_dht_keypair['ed25519']['public'], @_dht_keypair['ed25519']['private'])
						init		=
							method	: 'POST'
							# TODO: When https://github.com/bitinn/node-fetch/pull/457 is merged and released, remove `.buffer` as unnecessary
							body	: compose_signal(@_dht_keypair['ed25519']['public'], null_id, sdp, signature).buffer
						# Prefer HTTPS connection if possible, otherwise fallback to insecure (primarily for development purposes)
						fetch("https://#bootstrap_node", init)
							.catch (error) ->
								if typeof location == 'undefined' || location.protocol == 'http:'
									fetch("http://#bootstrap_node", init)
								else
									throw error
							.then (response) ->
								if !response['ok']
									throw 'Request failed'
								response['arrayBuffer']()
							.then (buffer) ->
								new Uint8Array(buffer)
							.then (command_data) !~>
								[source_id, target_id, sdp, signature]	= parse_signal(command_data)
								if !(
									detox-crypto['verify'](signature, sdp, source_id) &&
									are_arrays_equal(target_id, @_dht_keypair['ed25519']['public']) &&
									!@_transport['get_connection'](source_id)
								)
									throw 'Bad response'
								@_transport['update_peer_id'](random_id, source_id)
								connection['signal'](sdp)
							.catch (error) !->
								error_handler(error)
								connection['destroy']()
					)
					.'once'('connected', !~>
						connection['off']('disconnected', disconnected)
						done()
					)
					.'once'('disconnected', disconnected)
				!function disconnected
					done()
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
							rendezvous_token				= random_bytes(PUBLIC_KEY_LENGTH)
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
							for_signature					= concat_arrays([introduction_node, introduction_payload])
							signature						= detox-crypto['sign'](for_signature, real_public_key, real_keypair['ed25519']['private'])
							introduction_message			= concat_arrays([signature, introduction_payload])
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
							@_send_to_routing_path(
								first_node
								route_id
								ROUTING_COMMAND_INITIALIZE_CONNECTION
								compose_initialize_connection_data(rendezvous_token, introduction_node, target_id, introduction_message_encrypted)
							)
							@'fire'('connection_progress', real_public_key, target_id, CONNECTION_PROGRESS_INTRODUCTION_SENT)
							path_confirmation_timeout	= timeoutSet(@_options['timeouts']['CONNECTION_TIMEOUT'], !~>
								@_router['off']('data', path_confirmation)
								encryptor_instance['destroy']()
								try_to_introduce()
							)
						try_to_introduce()
					@_router['on']('data', found_introduction_nodes)
					@_send_to_routing_path(first_node, route_id, ROUTING_COMMAND_FIND_INTRODUCTION_NODES_REQUEST, target_id)
					find_introduction_nodes_timeout	= timeoutSet(@_options['timeouts']['CONNECTION_TIMEOUT'], !~>
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
		 * @param {!Uint8Array}	data			Size limit can be obtained with `get_max_data_size()` method, roughly 65KiB
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
			data_with_header	= concat_arrays([[command], data])
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
			# TODO: Probably check this in more places
			@_destroyed	= true
			# Bootstrap node immediately destroys router, no need to do it again
			if !@_bootstrap_node
				@_destroy_router()
			else if @_http_server
				@_http_server.close()
			@_transport['destroy']()
			@_dht['destroy']()
		_destroy_router : !->
			clearInterval(@_cleanup_interval)
			clearInterval(@_keep_announce_routes_interval)
			clearInterval(@_get_more_nodes_interval)
			@_routing_paths.forEach ([node_id, route_id]) !~>
				@_unregister_routing_path(node_id, route_id)
			@_pending_connections.forEach ([, , , connection_timeout]) !~>
				clearTimeout(connection_timeout)
			@_router['destroy']()
		/**
		 * @return {boolean}
		 */
		_more_aware_of_nodes_needed : ->
			!@_bootstrap_node && !!(@_aware_of_nodes.size < @_options['aware_of_nodes_limit'] || @_get_stale_aware_of_nodes(true).length)
		/**
		 * @param {boolean=} early_exit Will return single node if present, used to check if stale nodes are present at all
		 *
		 * @return {!Array<string>}
		 */
		_get_stale_aware_of_nodes : (early_exit = false) ->
			stale_aware_of_nodes	= []
			stale_older_than		= +(new Date) - @_options['timeouts']['STALE_AWARE_OF_NODE_TIMEOUT'] * 1000
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
		 * @param {!Uint8Array} peer_id
		 */
		_get_more_nodes_from : (peer_id) !->
			@_get_nodes_requested.add(peer_id)
			@_send_uncompressed_core_command(peer_id, UNCOMPRESSED_CORE_COMMAND_GET_NODES_REQUEST, empty_array)
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
			# TODO: Some trust model, only return trusted nodes
			if !@_connected_nodes.size
				# Make random lookup in order to fill DHT with known nodes
				@_random_lookup()
				return null
			connected_nodes		= Array.from(@_connected_nodes.values())
			exclude_nodes_set	= ArraySet(exclude_nodes.concat(Array.from(@_bootstrap_nodes_ids)))
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
		_random_lookup : ->
			@_dht['lookup'](fake_node_id(), @_options['lookup_number'])
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
				..catch (error) !->
					error_handler(error)
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
		 * @param {!Uint8Array}	peer_id
		 * @param {number}		command			0..9
		 * @param {!Uint8Array}	command_data
		 */
		_handle_compressed_core_command : (peer_id, command, command_data) !->
			switch command
				case COMPRESSED_CORE_COMMAND_SIGNAL
					[source_id, target_id, sdp, signature]	= parse_signal(command_data)
					if !detox-crypto['verify'](signature, sdp, source_id)
						@_peer_error(peer_id)
						return
					# If we are waiting for command - consume with callback
					waiting_for_signal_key		= concat_arrays([target_id, source_id])
					waiting_for_signal_callback	= @_waiting_for_signal.get(waiting_for_signal_key)
					if waiting_for_signal_callback
						@_waiting_for_signal.delete(waiting_for_signal_key)
						waiting_for_signal_callback(sdp, signature, command_data)
						return
					# If command targets our peer, forward it
					if @_connected_nodes.has(target_id) && are_arrays_equal(peer_id, source_id)
						@_send_compressed_core_command(target_id, COMPRESSED_CORE_COMMAND_SIGNAL, command_data)
						return
					# If command doesn't target ourselves - exit
					if !are_arrays_equal(target_id, @_dht_keypair['ed25519']['public'])
						return
					# Otherwise consume signal
					connection	= @_transport['get_connection'](source_id)
					if !connection
						connection	= @_transport['create_connection'](false, source_id)
						if !connection
							return
						connection['on']('signal', (sdp) !~>
							signature		= detox-crypto['sign'](sdp, @_dht_keypair['ed25519']['public'], @_dht_keypair['ed25519']['private'])
							command_data	= compose_signal(@_dht_keypair['ed25519']['public'], source_id, sdp, signature)
							@_send_compressed_core_command(peer_id, COMPRESSED_CORE_COMMAND_SIGNAL, command_data)
						)
					connection['signal'](sdp)
		/**
		 * @param {!Uint8Array}	peer_id
		 * @param {number}		command			0..9
		 * @param {!Uint8Array}	command_data
		 */
		_handle_uncompressed_core_command : (peer_id, command, command_data) !->
			switch command
				case UNCOMPRESSED_CORE_COMMAND_FORWARD_INTRODUCTION
					[target_id, introduction_message]	= parse_introduce_to_data(command_data)
					if !@_announcements_from.has(target_id)
						return
					[target_node_id, target_route_id]	= @_announcements_from.get(target_id)
					@_send_to_routing_path(target_node_id, target_route_id, ROUTING_COMMAND_INTRODUCTION, introduction_message)
				case UNCOMPRESSED_CORE_COMMAND_GET_NODES_REQUEST
					# TODO: This is a naive implementation, can be attacked relatively easily
					nodes			= @_pick_random_connected_nodes(7) || []
					nodes			= nodes.concat(@_pick_random_aware_of_nodes(10 - nodes.length) || [])
					command_data	= concat_arrays(nodes)
					@_send_uncompressed_core_command(peer_id, UNCOMPRESSED_CORE_COMMAND_GET_NODES_RESPONSE, command_data)
				case UNCOMPRESSED_CORE_COMMAND_GET_NODES_RESPONSE
					if !@_get_nodes_requested.has(peer_id)
						return
					@_get_nodes_requested.delete(peer_id)
					if !command_data.length || command_data.length % PUBLIC_KEY_LENGTH != 0
						return
					number_of_nodes			= command_data.length / PUBLIC_KEY_LENGTH
					stale_aware_of_nodes	= @_get_stale_aware_of_nodes()
					for i from 0 til number_of_nodes
						new_node_id	= command_data.subarray(i * PUBLIC_KEY_LENGTH, (i + 1) * PUBLIC_KEY_LENGTH)
						# Ignore already connected nodes and own ID or if there are enough nodes already
						if (
							are_arrays_equal(new_node_id, @_dht_keypair['ed25519']['public']) ||
							@_connected_nodes.has(new_node_id)
						)
							continue
						if @_aware_of_nodes.has(new_node_id) || @_aware_of_nodes.size < @_options['aware_of_nodes_limit']
							@_aware_of_nodes.set(new_node_id, +(new Date))
							@'fire'('aware_of_nodes_count', @_aware_of_nodes.size)
						else if stale_aware_of_nodes.length
							stale_node_to_remove = pull_random_item_from_array(stale_aware_of_nodes)
							@_aware_of_nodes.delete(stale_node_to_remove)
							@_aware_of_nodes.set(new_node_id, +(new Date))
							@'fire'('aware_of_nodes_count', @_aware_of_nodes.size)
						else
							break
				case UNCOMPRESSED_CORE_COMMAND_BOOTSTRAP_NODE
					@_bootstrap_nodes.add(array2string(command_data))
					@_bootstrap_nodes_ids.add(peer_id)
		/**
		 * @param {!Uint8Array}	peer_id
		 * @param {number}		command			0..9
		 * @param {!Uint8Array}	command_data
		 */
		_send_compressed_core_command : (peer_id, command, command_data) !->
			@_send(peer_id, command, command_data)
		/**
		 * @param {!Uint8Array}	peer_id
		 * @param {number}		command			0..9
		 * @param {!Uint8Array}	command_data
		 */
		_send_dht_command : (peer_id, command, command_data) !->
			@_send(peer_id, command + DHT_COMMANDS_OFFSET, command_data)
		/**
		 * @param {!Uint8Array}	peer_id
		 * @param {!Uint8Array}	data
		 */
		_send_routing_command : (peer_id, data) !->
			@_send(peer_id, ROUTING_COMMANDS, data)
		/**
		 * @param {!Uint8Array}	peer_id
		 * @param {number}		command			0..234
		 * @param {!Uint8Array}	command_data
		 */
		_send_uncompressed_core_command : (peer_id, command, command_data) !->
			@_send(peer_id, command + UNCOMPRESSED_CORE_COMMANDS_OFFSET, command_data)
		/**
		 * @param {!Uint8Array}	node_id
		 * @param {number}		command			0..255
		 * @param {!Uint8Array}	command_data
		 */
		_send : (node_id, command, command_data) !->
			if @_connected_nodes.has(node_id)
				@_update_connection_timeout(node_id)
				@_transport['send'](node_id, command, command_data)
				return
			!~function connected (new_node_id)
				if !are_arrays_equal(node_id, new_node_id)
					return
				clearTimeout(connected_timeout)
				@_transport['off']('connected', connected)
				@_update_connection_timeout(node_id)
				@_transport['send'](node_id, command, command_data)
			@_transport['on']('connected', connected)
			connected_timeout	= timeoutSet(@_options['timeouts']['CONNECTION_TIMEOUT'], !~>
				@_transport['off']('connected', connected)
			)
			@_dht['lookup'](node_id, @_options['lookup_number'])
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
			@_send_to_routing_path(node_id, route_id, command, data)
		/**
		 * @param {!Uint8Array} node_id
		 * @param {!Uint8Array} route_id
		 * @param {number}		command
		 * @param {!Uint8Array}	data
		 */
		_send_to_routing_path : (node_id, route_id, command, data) ->
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
			@_send_to_routing_path(node_id, route_id, ROUTING_COMMAND_PING, empty_array)
			true
		/**
		 * @param {!Uint8Array} node_id
		 */
		_update_connection_timeout : (node_id) !->
			# TODO: Probably track incoming and outgoing requests separately so that we can drop less important connections if needed
			@_connections_timeouts.set(node_id, +(new Date))
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
			time	= parseInt(+(new Date) / 1000, 10) # In seconds, should be enough if kept as unsigned 32-bit integer which we actually do
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
			@_dht['get_value'](target_public_key).then (introduction_nodes_bulk) ->
				if introduction_nodes_bulk.length % PUBLIC_KEY_LENGTH != 0
					throw ''
				introduction_nodes	= []
				for i from 0 til introduction_nodes_bulk.length / PUBLIC_KEY_LENGTH
					introduction_nodes.push(introduction_nodes_bulk.subarray(i * PUBLIC_KEY_LENGTH, (i + 1) * PUBLIC_KEY_LENGTH))
				introduction_nodes
		_peer_error : (peer_id) !->
			@_dht['del_peer'](peer_id)
			@_transport['destroy_connection'](peer_id)
			# TODO
		_peer_warning : (peer_id) !->
			# TODO

	Core:: = Object.assign(Object.create(async-eventer::), Core::)
	Object.defineProperty(Core::, 'constructor', {value: Core})
	{
		'ready'			: (callback) !->
			<-! detox-crypto['ready']
			<-! detox-dht['ready']
			<-! detox-routing['ready']
			callback()
		/**
		 * Generate random seed that can be used as keypair seed
		 *
		 * @return {!Uint8Array} 32 bytes
		 */
		'generate_seed'	: ->
			random_bytes(PUBLIC_KEY_LENGTH)
		'Core'			: Core
	}

# NOTE: `node-fetch` dependency is the last one and only specified for CommonJS, make sure to insert new dependencies before it
if typeof define == 'function' && define['amd']
	# AMD
	define(['@detox/crypto', '@detox/dht', '@detox/routing', '@detox/transport', '@detox/utils', 'fixed-size-multiplexer', 'async-eventer'], Wrapper)
else if typeof exports == 'object'
	# CommonJS
	module.exports = Wrapper(require('@detox/crypto'), require('@detox/dht'), require('@detox/routing'), require('@detox/transport'), require('@detox/utils'), require('fixed-size-multiplexer'), require('async-eventer'), require('node-fetch'))
else
	# Browser globals
	@'detox_core' = Wrapper(@'detox_crypto', @'detox_dht', @'detox_routing', @'detox_transport', @'detox_utils', @'fixed_size_multiplexer', @'async_eventer')
