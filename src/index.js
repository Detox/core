// Generated by LiveScript 1.5.0
/**
 * @package   Detox core
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
(function(){
  var DHT_COMMAND_ROUTING, DHT_COMMAND_INTRODUCE_TO, ROUTING_COMMAND_ANNOUNCE, ROUTING_COMMAND_INITIALIZE_CONNECTION, ROUTING_COMMAND_INTRODUCTION, ROUTING_COMMAND_CONFIRM_CONNECTION, ROUTING_COMMAND_CONNECTED, ROUTING_COMMAND_DATA, ID_LENGTH, SIGNATURE_LENGTH, CONNECTION_TIMEOUT, ROUTING_PATH_SEGMENT_TIMEOUT, LAST_USED_TIMEOUT, CONNECTION_ERROR_NOT_ENOUGH_CONNECTED_NODES, CONNECTION_ERROR_NO_INTRODUCTION_NODES, CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT, CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES, ANNOUNCEMENT_ERROR_NO_SUCCESSFUL_ANNOUNCEMENTS, randombytes;
  DHT_COMMAND_ROUTING = 0;
  DHT_COMMAND_INTRODUCE_TO = 1;
  ROUTING_COMMAND_ANNOUNCE = 0;
  ROUTING_COMMAND_INITIALIZE_CONNECTION = 1;
  ROUTING_COMMAND_INTRODUCTION = 2;
  ROUTING_COMMAND_CONFIRM_CONNECTION = 3;
  ROUTING_COMMAND_CONNECTED = 4;
  ROUTING_COMMAND_DATA = 5;
  ID_LENGTH = 32;
  SIGNATURE_LENGTH = 64;
  CONNECTION_TIMEOUT = 30;
  ROUTING_PATH_SEGMENT_TIMEOUT = 10;
  LAST_USED_TIMEOUT = 60;
  CONNECTION_ERROR_NOT_ENOUGH_CONNECTED_NODES = 0;
  CONNECTION_ERROR_NO_INTRODUCTION_NODES = 1;
  CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT = 2;
  CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES = 3;
  ANNOUNCEMENT_ERROR_NO_SUCCESSFUL_ANNOUNCEMENTS = 0;
  if (typeof crypto !== 'undefined') {
    randombytes = function(size){
      var array;
      array = new Uint8Array(size);
      crypto.getRandomValues(array);
      return array;
    };
  } else {
    randombytes = require('crypto').randomBytes;
  }
  /**
   * @param {number} min
   * @param {number} max
   *
   * @return {number}
   */
  function random_int(min, max){
    var bytes, uint32_number;
    bytes = randombytes(4);
    uint32_number = new Uint32Array(bytes.buffer)[0];
    return Math.floor(uint32_number / Math.pow(2, 32) * (max - min + 1)) + min;
  }
  /**
   * @param {!Array} array Returned item will be removed from this array
   *
   * @return {*}
   */
  function pull_random_item_from_array(array){
    var length, index;
    length = array.length;
    if (length === 1) {
      return array.pop();
    } else {
      index = random_int(0, length - 1);
      return array.splice(index, 1)[0];
    }
  }
  /**
   * @param {!Uint8Array}	address
   * @param {!Uint8Array}	segment_id
   *
   * @return {string}
   */
  function compute_source_id(address, segment_id){
    return address.join(',') + segment_id.join(',');
  }
  /**
   * @param {string}		string
   * @param {!Uint8Array}	array
   *
   * @return {boolean}
   */
  function is_string_equal_to_array(string, array){
    return string === array.join(',');
  }
  /**
   * @param {!Uint8Array} target_id
   * @param {!Uint8Array} introduction_node
   * @param {!Uint8Array} rendezvous_node
   * @param {!Uint8Array} rendezvous_token
   * @param {!Uint8Array} secret
   *
   * @return {!Uint8Array}
   */
  function generate_introduction_payload(target_id, introduction_node, rendezvous_node, rendezvous_token, secret){
    var x$;
    x$ = new Uint8Array(ID_LENGTH * 3 + secret.length);
    x$.set(target_id);
    x$.set(introduction_node, ID_LENGTH);
    x$.set(rendezvous_node, ID_LENGTH * 2);
    x$.set(rendezvous_token, ID_LENGTH * 3);
    x$.set(secret, ID_LENGTH * 4);
    return x$;
  }
  /**
   * @param {!Uint8Array} introduction_payload
   *
   * @return {!Array<Uint8Array>} [introduction_node, rendezvous_node, rendezvous_token, secret]
   */
  function parse_introduction_payload(introduction_payload){
    var target_id, introduction_node, rendezvous_node, rendezvous_token, secret;
    target_id = introduction_payload.subarray(0, ID_LENGTH);
    introduction_node = introduction_payload.subarray(ID_LENGTH, ID_LENGTH * 2);
    rendezvous_node = introduction_payload.subarray(ID_LENGTH * 2, ID_LENGTH * 3);
    rendezvous_token = introduction_payload.subarray(ID_LENGTH * 3, ID_LENGTH * 4);
    secret = introduction_payload.subarray(ID_LENGTH * 4);
    return [introduction_node, rendezvous_node, rendezvous_token, secret];
  }
  /**
   * @param {!Uint8Array} public_key
   * @param {!Uint8Array} announcement_message
   * @param {!Uint8Array} signature
   *
   * @return {!Uint8Array}
   */
  function compose_announcement_data(public_key, announcement_message, signature){
    var x$;
    x$ = new Uint8Array(ID_LENGTH + announcement_message.length);
    x$.set(public_key);
    x$.set(signature, ID_LENGTH);
    x$.set(announcement_message, ID_LENGTH + SIGNATURE_LENGTH);
    return x$;
  }
  /**
   * @param {!Uint8Array} message
   *
   * @return {!Array<Uint8Array>} [public_key, announcement_message, signature]
   */
  function parse_announcement_data(message){
    var public_key, announcement_message, signature;
    public_key = message.subarray(0, ID_LENGTH);
    announcement_message = message.subarray(ID_LENGTH, ID_LENGTH + SIGNATURE_LENGTH);
    signature = message.subarray(ID_LENGTH + SIGNATURE_LENGTH);
    return [public_key, announcement_message, signature];
  }
  /**
   * @param {!Uint8Array} rendezvous_token
   * @param {!Uint8Array} introduction_node
   * @param {!Uint8Array} target_id
   * @param {!Uint8Array} introduction_message
   *
   * @return {!Uint8Array}
   */
  function compose_initialize_connection_data(rendezvous_token, introduction_node, target_id, introduction_message){
    var x$;
    x$ = new Uint8Array(ID_LENGTH * 3 + introduction_message.length);
    x$.set(rendezvous_token);
    x$.set(introduction_node, ID_LENGTH);
    x$.set(target_id, ID_LENGTH * 2);
    x$.set(introduction_message, ID_LENGTH * 3);
    return x$;
  }
  /**
   * @param {!Uint8Array} message
   *
   * @return {!Array<Uint8Array>} [rendezvous_token, introduction_node, target_id, introduction_message]
   */
  function parse_initialize_connection_data(message){
    var rendezvous_token, introduction_node, target_id, introduction_message;
    rendezvous_token = message.subarray(0, ID_LENGTH);
    introduction_node = message.subarray(ID_LENGTH, ID_LENGTH * 2);
    target_id = message.subarray(ID_LENGTH * 2, ID_LENGTH * 3);
    introduction_message = message.subarray(ID_LENGTH * 3);
    return [rendezvous_token, introduction_node, target_id, introduction_message];
  }
  /**
   * @param {!Uint8Array} signature
   * @param {!Uint8Array} rendezvous_token
   *
   * @return {!Uint8Array}
   */
  function compose_confirm_connection_data(signature, rendezvous_token){
    var x$;
    x$ = new Uint8Array(SIGNATURE_LENGTH + rendezvous_token.length);
    x$.set(signature);
    x$.set(rendezvous_token, SIGNATURE_LENGTH);
    return x$;
  }
  /**
   * @param {!Uint8Array} message
   *
   * @return {!Array<Uint8Array>} [signature, rendezvous_token]
   */
  function parse_confirm_connection_data(message){
    var signature, rendezvous_token;
    signature = message.subarray(0, SIGNATURE_LENGTH);
    rendezvous_token = message.subarray(SIGNATURE_LENGTH);
    return [signature, rendezvous_token];
  }
  /**
   * @param {!Uint8Array} target_id
   * @param {!Uint8Array} introduction_message
   *
   * @return {!Uint8Array}
   */
  function compose_introduce_to_data(target_id, introduction_message){
    var x$;
    x$ = new Uint8Array(ID_LENGTH + introduction_message.length);
    x$.set(target_id);
    x$.set(introduction_message, ID_LENGTH);
    return x$;
  }
  /**
   * @param {!Uint8Array} message
   *
   * @return {!Array<Uint8Array>} [target_id, introduction_message]
   */
  function parse_introduce_to_data(message){
    var target_id, introduction_message;
    target_id = message.subarray(0, ID_LENGTH);
    introduction_message = message.subarray(ID_LENGTH);
    return [target_id, introduction_message];
  }
  function Wrapper(detoxCrypto, detoxTransport, asyncEventer){
    /**
     * Generate random seed that can be used as keypair seed
     *
     * @return {!Uint8Array} 32 bytes
     */
    var x$, y$;
    function generate_seed(){
      return detoxCrypto['create_keypair']()['seed'];
    }
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
    function Core(real_key_seed, dht_key_seed, bootstrap_nodes, ice_servers, packet_size, packets_per_second, bucket_size, max_pending_segments){
      var this$ = this;
      packet_size == null && (packet_size = 512);
      packets_per_second == null && (packets_per_second = 1);
      bucket_size == null && (bucket_size = 2);
      max_pending_segments == null && (max_pending_segments = 10);
      if (!(this instanceof Core)) {
        return new Core(real_key_seed, dht_key_seed, bootstrap_nodes, ice_servers, packet_size, packets_per_second, bucket_size, max_pending_segments);
      }
      asyncEventer.call(this);
      this._real_keypair = detoxCrypto['create_keypair'](real_key_seed);
      this._dht_keypair = detoxCrypto['create_keypair'](dht_key_seed);
      this._connected_nodes = new Map;
      this._routing_paths = new Map;
      this._id_to_routing_path = new Map;
      this._routing_path_to_id = new Map;
      this._used_tags = new Map;
      this._last_used_timeouts = new Map;
      this._pending_connection = new Map;
      this._announced_to = new Map;
      this._announcements_from = new Map;
      this._forwarding_mapping = new Map;
      this._dht = detoxTransport['DHT'](this._dht_keypair['ed25519']['public'], this._dht_keypair['ed25519']['private'], bootstrap_nodes, ice_servers, packet_size, packets_per_second, bucket_size);
      this._router = detoxTransport['Router'](this._dht_keypair['x25519']['private'], packet_size, max_pending_segments);
      this._sign = function(data){
        return detoxCrypto['sign'](data, this$._real_keypair['ed25519']['public'], this$._real_keypair['ed25519']['private']);
      };
      this._dht['on']('node_connected', function(node_id){
        this$._connected_nodes.set(node_id.join(','), node_id);
      })['on']('node_disconnected', function(node_id){
        this$._connected_nodes['delete'](node_id.join(','));
      })['on']('data', function(node_id, command, data){
        var ref$, target_id, introduction_message, target_id_string;
        switch (command) {
        case DHT_COMMAND_ROUTING:
          this$._router['process_packet'](node_id, data);
          break;
        case DHT_COMMAND_INTRODUCE_TO:
          ref$ = parse_introduce_to_data(data), target_id = ref$[0], introduction_message = ref$[1];
          target_id_string = target_id.join(',');
          if (!this$._announcements_from.has(target_id_string)) {
            return;
          }
          this$._send_to_routing_node(target_id, ROUTING_COMMAND_INTRODUCTION, introduction_message);
        }
      });
      this._router['on']('send', function(node_id, data){
        this$._send_to_dht_node(node_id, DHT_COMMAND_ROUTING, data);
      })['on']('data', function(node_id, route_id, command, data){
        var source_id, ref$, public_key, announcement_message, signature, public_key_string, rendezvous_token, introduction_node, target_id, introduction_message, rendezvous_token_string, connection_timeout, target_node_id, target_route_id, target_source_id, introduction_message_decrypted, introduction_payload, rendezvous_node, secret, origin_node_id;
        this$._update_used_timeout(node_id);
        source_id = compute_source_id(node_id, route_id);
        switch (command) {
        case ROUTING_COMMAND_ANNOUNCE:
          ref$ = parse_announcement_data(data), public_key = ref$[0], announcement_message = ref$[1], signature = ref$[2];
          if (!detoxCrypto['verify'](signature, announcement_message, public_key)) {
            return;
          }
          this$._register_routing_path(public_key, node_id, route_id);
          public_key_string = public_key.join(',');
          this$._announcements_from.set(public_key_string, public_key);
          this$['fire']('announcement_received', public_key);
          break;
        case ROUTING_COMMAND_INITIALIZE_CONNECTION:
          ref$ = parse_initialize_connection_data(data), rendezvous_token = ref$[0], introduction_node = ref$[1], target_id = ref$[2], introduction_message = ref$[3];
          rendezvous_token_string = rendezvous_token.join(',');
          connection_timeout = setTimeout(function(){
            this$._pending_connection['delete'](rendezvous_token_string);
          }, CONNECTION_TIMEOUT * 1000);
          this$._pending_connection.set(rendezvous_token_string, [node_id, route_id, target_id, connection_timeout]);
          this$._send_to_dht_node(introduction_node, DHT_COMMAND_INTRODUCE_TO, compose_introduce_to_data(target_id, introduction_message));
          break;
        case ROUTING_COMMAND_CONFIRM_CONNECTION:
          ref$ = parse_confirm_connection_data(data), signature = ref$[0], rendezvous_token = ref$[1];
          rendezvous_token_string = rendezvous_token.join(',');
          if (!this$._pending_connection.has(rendezvous_token_string)) {
            return;
          }
          ref$ = this$._pending_connection.get(rendezvous_token_string), target_node_id = ref$[0], target_route_id = ref$[1], target_id = ref$[2], connection_timeout = ref$[3];
          if (!detoxCrypto['verify'](signature, rendezvous_token, target_id)) {
            return;
          }
          clearTimeout(connection_timeout);
          this$._router['send_to'](target_node_id, target_route_id, ROUTING_COMMAND_CONNECTED, data);
          target_source_id = compute_source_id(target_node_id, target_route_id);
          this$._forwarding_mapping.set(source_id, [target_node_id, target_route_id]);
          this$._forwarding_mapping.set(target_source_id, [node_id, route_id]);
          break;
        case ROUTING_COMMAND_INTRODUCTION:
          if (!this$._routing_path_to_id.has(source_id)) {
            return;
          }
          try {
            introduction_message_decrypted = detoxCrypto['one_way_decrypt'](this$._real_keypair['x25519']['public'], data);
            signature = introduction_message_decrypted.subarray(0, SIGNATURE_LENGTH);
            introduction_payload = introduction_message_decrypted.subarray(SIGNATURE_LENGTH);
            ref$ = parse_introduction_payload(introduction_payload), target_id = ref$[0], introduction_node = ref$[1], rendezvous_node = ref$[2], rendezvous_token = ref$[3], secret = ref$[4];
            if (!is_string_equal_to_array(introduction_node.join(','), this$._routing_path_to_id.get(source_id)) || !detoxCrypto['verify'](signature, introduction_payload, target_id)) {
              return;
            }
            data = {
              'target_id': target_id,
              'secret': secret,
              'number_of_intermediate_nodes': null
            };
            this$['fire']('introduction', data).then(function(){
              var number_of_intermediate_nodes, nodes, first_node;
              number_of_intermediate_nodes = data['number_of_intermediate_nodes'];
              if (number_of_intermediate_nodes === null) {
                return;
              }
              nodes = this$._pick_random_nodes(number_of_intermediate_nodes);
              if (!nodes) {
                return;
              }
              nodes.push(rendezvous_node);
              first_node = nodes[0];
              this$._router['construct_routing_path'](nodes).then(function(route_id){
                var signature;
                this$._register_routing_path(target_id, first_node, route_id);
                signature = this$._sign(announcement_message);
                this$._send_to_routing_node(target_id, ROUTING_COMMAND_CONFIRM_CONNECTION, compose_confirm_connection_data(signature, rendezvous_token));
              })['catch'](function(){});
            });
          } catch (e$) {}
          break;
        case ROUTING_COMMAND_DATA:
          if (this$._forwarding_mapping.has(source_id)) {
            ref$ = this$._forwarding_mapping.get(source_id), target_node_id = ref$[0], target_route_id = ref$[1];
            this$._router['send_to'](target_node_id, target_route_id, ROUTING_COMMAND_DATA, data);
          } else if (this$._routing_path_to_id.has(source_id)) {
            origin_node_id = this$._routing_path_to_id.get(source_id);
            this$['fire']('data', origin_node_id, data);
          }
        }
      })['on']('destroyed', function(node_id, route_id){
        var source_id, origin_node_id;
        source_id = compute_source_id(node_id, route_id);
        if (!this$._routing_path_to_id.has(source_id)) {
          return;
        }
        origin_node_id = this$._routing_path_to_id.get(source_id);
        this$._unregister_routing_path(node_id, route_id);
      });
    }
    x$ = Core;
    x$['CONNECTION_ERROR_NOT_ENOUGH_CONNECTED_NODES'] = CONNECTION_ERROR_NOT_ENOUGH_CONNECTED_NODES;
    x$['CONNECTION_ERROR_NO_INTRODUCTION_NODES'] = CONNECTION_ERROR_NO_INTRODUCTION_NODES;
    x$['CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT'] = CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT;
    x$['CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES'] = CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES;
    x$['ANNOUNCEMENT_ERROR_NO_SUCCESSFUL_ANNOUNCEMENTS'] = ANNOUNCEMENT_ERROR_NO_SUCCESSFUL_ANNOUNCEMENTS;
    Core.prototype = Object.create(asyncEventer.prototype);
    y$ = Core.prototype;
    /**
     * @param {number} number_of_introduction_nodes
     * @param {number} number_of_intermediate_nodes	How many hops should be made until introduction node (not including it)
     */
    y$['announce'] = function(number_of_introduction_nodes, number_of_intermediate_nodes){
      var introduction_nodes, introductions_pending, introduction_nodes_confirmed, i$, len$, this$ = this;
      introduction_nodes = this._pick_random_nodes(number_of_introduction_nodes);
      introductions_pending = number_of_introduction_nodes;
      introduction_nodes_confirmed = [];
      function announced(introduction_node){
        var announcement_message, signature, i$, ref$, len$, introduction_node_string;
        if (introduction_node) {
          introduction_nodes_confirmed.push(introduction_node);
        }
        --introductions_pending;
        if (introductions_pending) {
          return;
        }
        if (!introduction_nodes_confirmed.length) {
          this$['fire']('announcement_failed', ANNOUNCEMENT_ERROR_NO_SUCCESSFUL_ANNOUNCEMENTS);
          return;
        }
        announcement_message = this$._dht['generate_announcement_message'](this$._real_keypair['ed25519']['public'], this$._real_keypair['ed25519']['private'], introduction_nodes_confirmed);
        signature = this$._sign(announcement_message);
        for (i$ = 0, len$ = (ref$ = introduction_nodes_confirmed).length; i$ < len$; ++i$) {
          introduction_node = ref$[i$];
          this$._send_to_routing_node(introduction_node, ROUTING_COMMAND_ANNOUNCE, compose_announcement_data(this$._real_keypair['ed25519']['public'], announcement_message, signature));
          introduction_node_string = introduction_node.join(',');
          this$._announced_to.set(introduction_node_string, introduction_node);
        }
        this$['fire']('announced');
      }
      for (i$ = 0, len$ = introduction_nodes.length; i$ < len$; ++i$) {
        (fn$.call(this, introduction_nodes[i$]));
      }
      function fn$(introduction_node){
        var nodes, first_node, this$ = this;
        nodes = this._pick_random_nodes(number_of_intermediate_nodes);
        if (!nodes) {
          return;
        }
        nodes.push(introduction_node);
        first_node = nodes[0];
        this._router['construct_routing_path'](nodes).then(function(route_id){
          this$._register_routing_path(introduction_node, first_node, route_id);
          announced(introduction_node);
        })['catch'](function(){
          announced();
        });
      }
    };
    /**
     * @param {!Uint8Array}	target_id						Real Ed25519 pubic key of interested node
     * @param {!Uint8Array}	secret
     * @param {number}		number_of_intermediate_nodes	How many hops should be made until rendezvous node (not including it)
     */
    y$['connect_to'] = function(target_id, secret, number_of_intermediate_nodes){
      var this$ = this;
      if (!number_of_intermediate_nodes) {
        throw new Error('Direct connections are not yet supported');
        return;
      }
      if (this._id_to_routing_path.has(target_id.join(','))) {
        return;
      }
      this._dht['find_introduction_nodes'](target_id, function(introduction_nodes){
        var connected_nodes, nodes, first_node, rendezvous_node;
        if (!introduction_nodes.length) {
          this$['fire']('connection_failed', target_id, CONNECTION_ERROR_NO_INTRODUCTION_NODES);
          return;
        }
        connected_nodes = Array.from(this$._connected_nodes.values());
        nodes = this$._pick_random_nodes(number_of_intermediate_nodes + 1);
        if (!nodes) {
          this$['fire']('connection_failed', target_id, CONNECTION_ERROR_NOT_ENOUGH_CONNECTED_NODES);
          return;
        }
        first_node = nodes[0];
        rendezvous_node = nodes[nodes.length - 1];
        this$._router['construct_routing_path'](nodes).then(function(route_id){
          function try_to_introduce(){
            var introduction_node, rendezvous_token, introduction_payload, signature, x25519_public_key, introduction_message, first_node_string, route_id_string, path_confirmation_timeout;
            if (!introduction_nodes.length) {
              this$['fire']('connection_failed', target_id, CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES);
              return;
            }
            introduction_node = pull_random_item_from_array(introduction_nodes);
            rendezvous_token = randombytes(ID_LENGTH);
            introduction_payload = generate_introduction_payload(this$._real_keypair['ed25519']['public'], introduction_node, rendezvous_node, rendezvous_token, secret);
            signature = this$._sign(introduction_payload);
            x25519_public_key = detoxCrypto['convert_public_key'](target_id);
            introduction_message = detoxCrypto['one_way_encrypt'](x25519_public_key, new Uint8Array(introduction_payload.length + signature.length), y$.set(signature), y$.set(introduction_payload, SIGNATURE_LENGTH));
            first_node_string = first_node.join(',');
            route_id_string = route_id.join(',');
            function path_confirmation(node_id, route_id, command, data){
              if (!is_string_equal_to_array(first_node_string, node_id) || !is_string_equal_to_array(responder_id_string, route_id) || command !== ROUTING_COMMAND_CONNECTED || data.subarray(0, ID_LENGTH).join(',') !== rendezvous_token.join(',') || !detoxCrypto['verify'](data.subarray(ID_LENGTH, ID_LENGTH + SIGNATURE_LENGTH), rendezvous_token, target_id)) {
                return;
              }
              clearTimeout(path_confirmation_timeout);
              this$._register_routing_path(target_id, node_id, route_id);
            }
            this$._router['on']('data', path_confirmation);
            this$._router['send_to'](first_node, route_id, ROUTING_COMMAND_INITIALIZE_CONNECTION, compose_initialize_connection_data(rendezvous_token, introduction_node, target_id, introduction_message));
            path_confirmation_timeout = setTimeout(function(){
              this$._ronion['off']('data', path_confirmation);
              try_to_introduce();
            }, CONNECTION_TIMEOUT * 1000);
          }
          try_to_introduce();
        })['catch'](function(){
          this$['fire']('connection_failed', target_id, CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT);
          return;
        });
      }, function(){
        this$['fire']('connection_failed', target_id, CONNECTION_ERROR_NO_INTRODUCTION_NODES);
      });
    };
    /**
     * @param {!Uint8Array} target_id
     * @param {!Uint8Array} data
     */
    y$['send_to'] = function(target_id, data){
      this._send_to_routing_node(target_id, ROUTING_COMMAND_DATA, data);
    };
    /**
     * Get some random nodes suitable for constructing routing path through them or for acting as introduction nodes
     *
     * @param {number}				number_of_nodes
     * @param {Array<Uint8Array>}	exclude_nodes
     *
     * @return {Array<Uint8Array>} `null` if there was not enough nodes
     */
    y$._pick_random_nodes = function(number_of_nodes, exclude_nodes){
      var connected_nodes, i$, i, results$ = [];
      exclude_nodes == null && (exclude_nodes = null);
      if (this._connected_nodes.size / 3 < number_of_nodes) {
        return null;
      }
      connected_nodes = Array.from(this._connected_nodes.values());
      if (exclude_nodes) {
        connected_nodes = connected_nodes.filter(function(node){
          return !in$(node, exclude_nodes);
        });
      }
      for (i$ = 0; i$ < number_of_nodes; ++i$) {
        i = i$;
        results$.push(pull_random_item_from_array(connected_nodes));
      }
      return results$;
    };
    /**
     * @param {!Uint8Array} target_id	Last node in routing path, responder
     * @param {!Uint8Array} node_id		First node in routing path, used for routing path identification
     * @param {!Uint8Array} route_id	ID of the route on `node_id`
     */
    y$._register_routing_path = function(target_id, node_id, route_id){
      var source_id, target_id_string;
      source_id = compute_source_id(node_id, route_id);
      target_id_string = target_id.join(',');
      if (this._routing_paths.has(source_id)) {
        return;
      }
      this._routing_paths.set(source_id, [node_id, route_id]);
      this._id_to_routing_path.set(target_id_string, [node_id, route_id]);
      this._routing_path_to_id.set(source_id, target_id);
      this['fire']('connected', target_id);
    };
    /**
     * @param {!Uint8Array} node_id		First node in routing path, used for routing path identification
     * @param {!Uint8Array} route_id	ID of the route on `node_id`
     */
    y$._unregister_routing_path = function(node_id, route_id){
      var source_id, target_id, target_id_string;
      source_id = compute_source_id(node_id, route_id);
      if (!this._routing_paths.has(source_id)) {
        return;
      }
      target_id = this._routing_path_to_id.get(source_id);
      target_id_string = target_id.join(',');
      this._routing_paths['delete'](source_id);
      this._routing_path_to_id['delete'](source_id);
      this._id_to_routing_path['delete'](target_id_string);
      this._announced_to['delete'](target_id_string);
      this._announcements_from['delete'](target_id_string);
      this['fire']('disconnected', target_id);
    };
    /**
     * @param {!Uint8Array}	node_id
     * @param {number}		command	0..245
     * @param {!Uint8Array}	data
     */
    y$._send_to_dht_node = function(node_id, command, data){
      var node_id_string, connected_timeout, this$ = this;
      node_id_string = node_id.join(',');
      if (this._connected_nodes.has(node_id_string)) {
        this._update_used_timeout(node_id);
        this._dht['send_data'](node_id, command, data);
        return;
      }
      function connected(node_id){
        if (!is_string_equal_to_array(node_id_string, node_id)) {
          return;
        }
        clearTimeout(connected_timeout);
        this$._update_used_timeout(node_id);
        this$._dht['send_data'](node_id, command, data);
      }
      this._dht['on']('node_connected', connected);
      connected_timeout = setTimeout(function(){
        this$._dht['off']('node_connected', connected);
      }, ROUTING_PATH_SEGMENT_TIMEOUT * 1000);
      this._dht['lookup'](node_id);
    };
    /**
     * @param {!Uint8Array}	target_id
     * @param {number}		command		0..245
     * @param {!Uint8Array}	data
     */
    y$._send_to_routing_node = function(target_id, command, data){
      var target_id_string, ref$, node_id, route_id;
      target_id_string = target_id.join(',');
      if (!this._id_to_routing_path.has(target_id_string)) {
        return;
      }
      ref$ = this._id_to_routing_path.get(target_id_string), node_id = ref$[0], route_id = ref$[1];
      this._router['send_data'](node_id, route_id, command, data);
    };
    /**
     * @param {!Uint8Array} node_id
     */
    y$._update_used_timeout = function(node_id){
      var node_id_string, last_sent_timeout, this$ = this;
      node_id_string = node_id.join(',');
      if (this._last_used_timeouts.has(node_id_string)) {
        clearTimeout(this._last_used_timeouts.get(node_id_string));
      } else {
        this._add_used_tag(node_id);
      }
      last_sent_timeout = setTimeout(function(){
        this$._last_used_timeouts['delete'](node_id_string);
        this$._del_used_tag(node_id);
      }, LAST_USED_TIMEOUT * 1000);
      this._last_used_timeouts.set(node_id_string, last_sent_timeout);
    };
    /**
     * @param {!Uint8Array} node_id
     */
    y$._add_used_tag = function(node_id){
      var node_id_string, value;
      node_id_string = node_id.join(',');
      value = 0;
      if (this._used_tags.has(node_id_string)) {
        value = this._used_tags.get(node_id_string);
      }
      ++value;
      this._used_tags.set(node_id_string, value);
      if (value === 1) {
        this._dht['add_used_tag'](node_id);
      }
    };
    /**
     * @param {!Uint8Array} node_id
     */
    y$._del_used_tag = function(node_id){
      var node_id_string, value;
      node_id_string = node_id.join(',');
      if (!this._used_tags.has(node_id_string)) {
        return;
      }
      value = this._used_tags.get(node_id_string);
      --value;
      if (!value) {
        this._used_tags['delete'](node_id_string);
        this._dht['del_used_tag'](node_id);
      } else {
        this._used_tags.set(node_id_string, value);
      }
    };
    Object.defineProperty(Core.prototype, 'constructor', {
      enumerable: false,
      value: Core
    });
    return {
      'ready': function(callback){
        var wait_for;
        wait_for = 2;
        function ready(){
          --wait_for;
          if (!wait_for) {
            callback();
          }
        }
        detoxCrypto['ready'](ready);
        detoxTransport['ready'](ready);
      },
      'generate_seed': generate_seed,
      'Core': Core
    };
  }
  if (typeof define === 'function' && define['amd']) {
    define(['@detox/crypto', '@detox/transport', 'async-eventer'], Wrapper);
  } else if (typeof exports === 'object') {
    module.exports = Wrapper(require('@detox/crypto'), require('@detox/transport').require('async-eventer'));
  } else {
    this['detox_core'] = Wrapper(this['detox_crypto'], this['detox_transport'], this['async_eventer']);
  }
  function in$(x, xs){
    var i = -1, l = xs.length >>> 0;
    while (++i < l) if (x === xs[i]) return true;
    return false;
  }
}).call(this);
