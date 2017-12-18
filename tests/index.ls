/**
 * @package   Detox core
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
detox-crypto	= require('@detox/crypto')
lib				= require('..')
test			= require('tape')

const NUMBER_OF_NODES = 10

bootstrap_ip	= '127.0.0.1'
bootstrap_port	= 16882

<-! lib.ready
test('Core', (t) !->
	t.plan(NUMBER_OF_NODES + 2)

	bootstrap_node_info	=
		node_id	: Buffer(detox-crypto.create_keypair(new Uint8Array(32)).ed25519.public).toString('hex')
		host	: bootstrap_ip
		port	: bootstrap_port

	nodes	= []

	i = 0
	!function start_node
		real_seed	= new Uint8Array(32)
			..set([i, 1])
		dht_seed	= new Uint8Array(32)
			..set([i])
		if i == 0
			instance	= lib.Core(real_seed, dht_seed, [], [], 5, 3)
			instance.start_bootstrap_node(bootstrap_ip, bootstrap_port)
		else
			instance	= lib.Core(real_seed, dht_seed, [bootstrap_node_info], [], 5)
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
		node_12	= nodes[12]
		node_19	= nodes[19]

		t.deepEqual(node_1.get_bootstrap_nodes()[0], bootstrap_node_info, 'Bootstrap nodes are returned correctly')

		node_1
			.once('announced', !->
				t.pass('Announced successfully')

				destroy_nodes()
			)
			.once('announcement_failed', (reason) !->
				t.fail('Announcement failed with ' + reason)

				destroy_nodes()
			)
		console.log 'Announcing...'
		node_1.announce(2, 1)
)
