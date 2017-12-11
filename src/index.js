// Generated by LiveScript 1.5.0
/**
 * @package   Detox core
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
(function(){
  var DHT_COMMAND_ROUTING, DHT_COMMAND_INTRODUCE_TO, ROUTING_COMMAND_ANNOUNCE, ROUTING_COMMAND_INITIALIZE_FORWARDING, ROUTING_COMMAND_CONFIRM_FORWARDING, ROUTING_COMMAND_CONNECTED, ID_LENGTH, SIGNATURE_LENGTH, CONNECTION_TIMEOUT, ROUTING_PATH_SEGMENT_TIMEOUT, LAST_USED_TIMEOUT, CONNECTION_ERROR_NOT_ENOUGH_CONNECTED_NODES, CONNECTION_ERROR_NO_INTRODUCTION_NODES, CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT, CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES, randombytes;
  DHT_COMMAND_ROUTING = 0;
  DHT_COMMAND_INTRODUCE_TO = 1;
  ROUTING_COMMAND_ANNOUNCE = 0;
  ROUTING_COMMAND_INITIALIZE_FORWARDING = 1;
  ROUTING_COMMAND_CONFIRM_FORWARDING = 2;
  ROUTING_COMMAND_CONNECTED = 3;
  ID_LENGTH = 32;
  SIGNATURE_LENGTH = 64;
  CONNECTION_TIMEOUT = 30;
  ROUTING_PATH_SEGMENT_TIMEOUT = 10;
  LAST_USED_TIMEOUT = 60;
  CONNECTION_ERROR_NOT_ENOUGH_CONNECTED_NODES = 0;
  CONNECTION_ERROR_NO_INTRODUCTION_NODES = 1;
  CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT = 2;
  CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES = 3;
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
   * @param {!Uint8Array} introduction_node
   * @param {!Uint8Array} rendezvous_node
   * @param {!Uint8Array} rendezvous_token
   * @param {!Uint8Array} secret
   *
   * @return {!Uint8Array}
   */
  function create_invitation_payload(introduction_node, rendezvous_node, rendezvous_token, secret){
    var x$;
    x$ = new Uint8Array(ID_LENGTH * 3 + secret.length);
    x$.set(introduction_node);
    x$.set(rendezvous_node, ID_LENGTH);
    x$.set(rendezvous_token, ID_LENGTH * 2);
    x$.set(secret, ID_LENGTH * 3);
    return x$;
  }
  /**
   * @param {!Uint8Array} invitation_payload
   *
   * @return {!Array<Uint8Array>} [introduction_node, rendezvous_node, rendezvous_token, secret]
   */
  function parse_invitation_payload(invitation_payload){
    var introduction_node, rendezvous_node, rendezvous_token, secret;
    introduction_node = invitation_payload.subarray(0, ID_LENGTH);
    rendezvous_node = invitation_payload.subarray(ID_LENGTH, ID_LENGTH * 2);
    rendezvous_token = invitation_payload.subarray(ID_LENGTH * 2, ID_LENGTH * 3);
    secret = invitation_payload.subarray(ID_LENGTH * 3);
    return [introduction_node, rendezvous_node, rendezvous_token, secret];
  }
  /**
   * @param {!Uint8Array} rendezvous_token
   * @param {!Uint8Array} introduction_node
   * @param {!Uint8Array} target_id
   * @param {!Uint8Array} invitation_message
   */
  function compose_initialize_forwarding_data(rendezvous_token, introduction_node, target_id, invitation_message){
    var x$;
    x$ = new Uint8Array(ID_LENGTH * 3 + invitation_message.length);
    x$.set(rendezvous_token);
    x$.set(introduction_node, ID_LENGTH);
    x$.set(target_id, ID_LENGTH * 2);
    x$.set(invitation_message, ID_LENGTH * 3);
    return x$;
  }
  /**
   * @param {!Uint8Array} message
   *
   * @return {!Array<Uint8Array>} [rendezvous_token, introduction_node, target_id, invitation_message]
   */
  function parse_initialize_forwarding_data(message){
    var rendezvous_token, introduction_node, target_id, invitation_message;
    rendezvous_token = message.subarray(0, ID_LENGTH);
    introduction_node = message.subarray(ID_LENGTH, ID_LENGTH * 2);
    target_id = message.subarray(ID_LENGTH * 2, ID_LENGTH * 3);
    invitation_message = message.subarray(ID_LENGTH * 3);
    return [rendezvous_token, introduction_node, target_id, invitation_message];
  }
  /**
   * @param {!Uint8Array} target_id
   * @param {!Uint8Array} invitation_message
   *
   * @return {!Uint8Array}
   */
  function compose_introduce_to_data(target_id, invitation_message){
    var x$;
    x$ = new Uint8Array(ID_LENGTH + invitation_message.length);
    x$.set(target_id);
    x$.set(invitation_message, ID_LENGTH);
    return x$;
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
      this._pending_forwarding = new Map;
      this._dht = detoxTransport['DHT'](this._dht_keypair['ed25519']['public'], this._dht_keypair['ed25519']['private'], bootstrap_nodes, ice_servers, packet_size, packets_per_second, bucket_size);
      this._router = detoxTransport['Router'](this._dht_keypair['x25519']['private'], packet_size, max_pending_segments);
      this._dht['on']('node_connected', function(node_id){
        this$._connected_nodes.set(node_id.join(','), node_id);
      })['on']('node_disconnected', function(node_id){
        this$._connected_nodes['delete'](node_id.join(','));
      })['on']('data', function(node_id, command, data){
        var target_id, invitation_message;
        switch (command) {
        case DHT_COMMAND_ROUTING:
          this$._router['process_packet'](node_id, data);
          break;
        case DHT_COMMAND_INTRODUCE_TO:
          target_id = data.subarray(1, 1 + ID_LENGTH);
          invitation_message = data.subarray(1 + ID_LENGTH);
        }
      });
      this._router['on']('send', function(node_id, data){
        this$._send_to_dht_node(node_id, DHT_COMMAND_ROUTING, data);
      })['on']('data', function(node_id, route_id, command, data){
        var source_id, origin_node_id, ref$, rendezvous_token, introduction_node, target_id, invitation_message, rendezvous_token_string, forwarding_timeout;
        this$._update_used_timeout(node_id);
        source_id = compute_source_id(node_id, route_id);
        if (this$._routing_path_to_id.has(source_id)) {
          origin_node_id = this$._routing_path_to_id.get(source_id);
          this$['fire']('data', origin_node_id, data);
        } else {
          switch (command) {
          case ROUTING_COMMAND_ANNOUNCE:
            break;
          case ROUTING_COMMAND_INITIALIZE_FORWARDING:
            ref$ = parse_initialize_forwarding_data(data), rendezvous_token = ref$[0], introduction_node = ref$[1], target_id = ref$[2], invitation_message = ref$[3];
            rendezvous_token_string = rendezvous_token.join(',');
            forwarding_timeout = setTimeout(function(){
              this$._pending_forwarding['delete'](rendezvous_token_string);
            }, CONNECTION_TIMEOUT * 1000);
            this$._pending_forwarding.set(rendezvous_token_string, [node_id, route_id, forwarding_timeout]);
            this$._send_to_dht_node(introduction_node, DHT_COMMAND_INTRODUCE_TO, compose_introduce_to_data(target_id, invitation_message));
            break;
          case ROUTING_COMMAND_CONFIRM_FORWARDING:
          }
        }
      })['on']('destroyed', function(node_id, route_id){
        var source_id, origin_node_id;
        source_id = compute_source_id(node_id, route_id);
        if (!this$._routing_path_to_id.has(source_id)) {
          return;
        }
        origin_node_id = this$._routing_path_to_id.get(source_id);
        this$['fire']('disconnected', origin_node_id);
        this$._unregister_routing_path(node_id, route_id);
      });
    }
    x$ = Core;
    x$['CONNECTION_ERROR_NOT_ENOUGH_CONNECTED_NODES'] = CONNECTION_ERROR_NOT_ENOUGH_CONNECTED_NODES;
    x$['CONNECTION_ERROR_NO_INTRODUCTION_NODES'] = CONNECTION_ERROR_NO_INTRODUCTION_NODES;
    x$['CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT'] = CONNECTION_ERROR_CANT_CONNECT_TO_RENDEZVOUS_POINT;
    x$['CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES'] = CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES;
    Core.prototype = Object.create(asyncEventer.prototype);
    y$ = Core.prototype;
    /**
     * @param {!Uint8Array}	target_id
     * @param {!Uint8Array}	secret
     * @param {number}		number_of_intermediate_nodes	How many hops should be made til rendezvous node
     */
    y$['connect_to'] = function(target_id, secret, number_of_intermediate_nodes){
      var this$ = this;
      if (!number_of_intermediate_nodes) {
        return;
      }
      if (this._connected_nodes.size / 2 < number_of_intermediate_nodes) {
        this['fire']('connection_failed', target_id, CONNECTION_ERROR_NOT_ENOUGH_CONNECTED_NODES);
        return;
      }
      this._dht['find_introduction_nodes'](target_id, function(introduction_nodes){
        var connected_nodes, nodes, res$, i$, to$, i, first_node, rendezvous_node;
        if (!introduction_nodes.length) {
          this$['fire']('connection_failed', target_id, CONNECTION_ERROR_NO_INTRODUCTION_NODES);
          return;
        }
        connected_nodes = this$._connected_nodes.slice();
        res$ = [];
        for (i$ = 0, to$ = number_of_intermediate_nodes; i$ < to$; ++i$) {
          i = i$;
          res$.push(pull_random_item_from_array(connected_nodes));
        }
        nodes = res$;
        first_node = nodes[0];
        rendezvous_node = nodes[nodes.length - 1];
        this$._router['construct_routing_path'](nodes).then(function(route_id){
          function try_to_introduce(){
            var introduction_node, rendezvous_token, invitation_payload, signature, x25519_public_key, invitation_message, first_node_string, route_id_string, path_confirmation_timeout;
            if (!introduction_nodes.length) {
              this$._router['destroy_routing_path'](first_node, route_id);
              this$['fire']('connection_failed', target_id, CONNECTION_ERROR_OUT_OF_INTRODUCTION_NODES);
              return;
            }
            introduction_node = pull_random_item_from_array(introduction_nodes);
            rendezvous_token = randombytes(ID_LENGTH);
            invitation_payload = create_invitation_payload(introduction_node, rendezvous_node, rendezvous_token, secret);
            signature = detoxCrypto['sign'](invitation_payload, this$._real_keypair['ed25519']['public'], this$._real_keypair['ed25519']['private']);
            x25519_public_key = detoxCrypto['convert_public_key'](target_id);
            invitation_message = detoxCrypto['one_way_encrypt'](x25519_public_key, new Uint8Array(invitation_payload.length + signature.length), y$.set(invitation_payload), y$.set(signature, invitation_payload.length));
            first_node_string = first_node.join(',');
            route_id_string = route_id.join(',');
            function path_confirmation(node_id, route_id, data){
              if (!is_string_equal_to_array(first_node_string, node_id) || !is_string_equal_to_array(responder_id_string, route_id) || data[0] !== ROUTING_COMMAND_CONNECTED || data.subarray(1, ID_LENGTH + 1).join(',') !== rendezvous_token.join(',')) {
                return;
              }
              clearTimeout(path_confirmation_timeout);
              this$._register_routing_path(target_id, node_id, route_id);
              this$['fire']('connected', target_id);
            }
            this$._router['on']('data', path_confirmation);
            this$._router['send_to'](first_node, route_id, ROUTING_COMMAND_INITIALIZE_FORWARDING, compose_initialize_forwarding_data(rendezvous_token, introduction_node, target_id, invitation_message));
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
     */
    y$['disconnect_from'] = function(target_id){
      var id_string, ref$, node_id, route_id;
      id_string = target_id.join(',');
      if (!this._id_to_routing_path.has(id_string)) {
        return;
      }
      ref$ = this._id_to_routing_path.get(id_string), node_id = ref$[0], route_id = ref$[1];
      this._router['destroy_routing_path'](node_id, route_id);
      this._unregister_routing_path(node_id, route_id);
    };
    /**
     * @param {!Uint8Array} target_id
     * @param {!Uint8Array} data
     */
    y$['send_to'] = function(target_id, data){
      var id_string, ref$, node_id, route_id;
      id_string = target_id.join(',');
      if (!this._id_to_routing_path.has(id_string)) {
        return;
      }
      ref$ = this._id_to_routing_path.get(id_string), node_id = ref$[0], route_id = ref$[1];
      this._router['send_data'](node_id, route_id, data);
    };
    /**
     * @param {!Uint8Array} responder_id	Last node in routing path, responder
     * @param {!Uint8Array} node_id			First node in routing path, used for routing path identification
     * @param {!Uint8Array} route_id		ID of the route on `node_id`
     */
    y$._register_routing_path = function(responder_id, node_id, route_id){
      var source_id, responder_id_string;
      source_id = compute_source_id(node_id, route_id);
      responder_id_string = responder_id.join(',');
      if (this._routing_paths.has(source_id)) {
        return;
      }
      this._routing_paths.set(source_id, [node_id, route_id]);
      this._id_to_routing_path.set(responder_id_string, [node_id, route_id]);
      this._routing_path_to_id.set(source_id, responder_id);
    };
    /**
     * @param {!Uint8Array} node_id		First node in routing path, used for routing path identification
     * @param {!Uint8Array} route_id	ID of the route on `node_id`
     */
    y$._unregister_routing_path = function(node_id, route_id){
      var source_id, responder_id_string;
      source_id = compute_source_id(node_id, route_id);
      if (!this._routing_paths.has(source_id)) {
        return;
      }
      responder_id_string = this._routing_path_to_id.get(source_id).join(',');
      this._routing_paths['delete'](source_id);
      this._routing_path_to_id['delete'](source_id);
      this._id_to_routing_path['delete'](responder_id_string);
    };
    /**
     * @param {!Uint8Array} node_id
     * @param {!Uint8Array} data
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
}).call(this);
