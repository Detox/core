/**
 * @package   Detox core
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
detox-crypto	= require('@detox/crypto')
lib				= require('..')
test			= require('tape')

const NUMBER_OF_NODES = 12

bootstrap_ip	= '127.0.0.1'
bootstrap_port	= 16882

<-! lib.ready
test('Core', (t) !->
	t.plan(NUMBER_OF_NODES + 4)

	bootstrap_node_info	=
		node_id	: Buffer(detox-crypto.create_keypair(new Uint8Array(32)).ed25519.public).toString('hex')
		host	: bootstrap_ip
		port	: bootstrap_port

	node_1_real_public_key	= detox-crypto.create_keypair(
		(new Uint8Array(32)
			..set([1, 1])
		)
	).ed25519.public
	node_1_secret			= Buffer.from('c2fd7c6349f0bb25ed28', 'hex')

	nodes	= []
	global.nodes = nodes

	i = 0
	!function start_node
		real_seed	= new Uint8Array(32)
			..set([i, 1])
		dht_seed	= new Uint8Array(32)
			..set([i])
		if i == 0
			instance	= lib.Core(real_seed, dht_seed, [], [], 2, 10)
			instance.start_bootstrap_node(bootstrap_ip, bootstrap_port)
		else
			instance	= lib.Core(real_seed, dht_seed, [bootstrap_node_info], [], 2)
		instance.once('ready', !->
			t.pass('Node ' + i + ' is ready')

			++i
			if i < NUMBER_OF_NODES
				start_node()
			else
				ready_callback()
		)
		nodes.push(instance)
	start_node()

	!function destroy_nodes
		for node in nodes
			node.destroy()

	!function ready_callback
		node_1	= nodes[1]
		node_7	= nodes[7]

		t.deepEqual(node_1.get_bootstrap_nodes()[0], bootstrap_node_info, 'Bootstrap nodes are returned correctly')

		node_1
			.once('announced', !->
				t.pass('Announced successfully')

				target_id	= node_1._real
				node_1.once('introduction', (data) !->
					t.equal(data.secret.join(','), node_1_secret.join(','), 'Correct secret on introduction')
					data.number_of_intermediate_nodes	= 1
				)
				node_7.once('connected', (target_id) !->
					if target_id.join(',') == node_1_real_public_key.join(',')
						t.pass('Connected successfully')

						destroy_nodes()
				)
				node_7.once('connection_failed', (, reason) !->
					t.fail('Connection failed with code ' + reason)

					destroy_nodes()
				)

				console.log 'Preparing for connection (8s)...'
				# Hack to make sure at least one announcement reaches corresponding DHT node at this point
				setTimeout (!->
					console.log 'Connecting...'
					node_7.connect_to(node_1_real_public_key, node_1_secret, 1)
				), 8000
			)
			.once('announcement_failed', (reason) !->
				t.fail('Announcement failed with code ' + reason)

				destroy_nodes()
			)
		console.log 'Announcing...'
		node_1.announce(2, 1)
)
