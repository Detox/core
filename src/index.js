// Generated by LiveScript 1.5.0
/**
 * @package   Detox core
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
(function(){
  function Wrapper(detoxCrypto, detoxTransport, asyncEventer){
    /**
     * Generate random seed that can be used as keypair seed
     *
     * @return {!Uint8Array} 32 bytes
     */
    var x$;
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
      this._dht = detoxTransport['DHT'](this._dht_keypair['ed25519']['public'], this._dht_keypair['ed25519']['private'], bootstrap_nodes, ice_servers, packet_size, packets_per_second, bucket_size);
      this._router = detoxTransport['Router'](this._dht_keypair['x25519']['private'], packet_size, max_pending_segments);
      this._dht['on']('node_connected', function(id){
        this$._connected_nodes.set(id.join(','), id);
      })['on']('node_disconnected', function(id){
        this$._connected_nodes['delete'](id.join(','));
      })['on']('data', function(id, data){
        this$._router['process_packet'](id, data);
      });
      this._router['on']('send', function(id, data){
        this$._dht['send_data'](id, data);
      })['on']('data', function(node_id, route_id, data){});
    }
    Core.prototype = Object.create(asyncEventer.prototype);
    x$ = Core.prototype;
    x$['connect_to'] = function(id){};
    x$['disconnect_from'] = function(id){};
    /**
     * @param {!Uint8Array} id		ID of the node that should receive data
     * @param {!Uint8Array} data
     */
    x$['send_data'] = function(id, data){};
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
