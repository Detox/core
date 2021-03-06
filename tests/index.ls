/**
 * @package Detox core
 * @author  Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @license 0BSD
 */
require('@detox/simple-peer-mock').register()

detox-crypto	= require('@detox/crypto')
lib				= require('..')
test			= require('tape')

const NUMBER_OF_NODES = 50

bootstrap_ip		= '127.0.0.1'
bootstrap_address	= 'localhost'
bootstrap_port		= 16882

command		= 38
data		= Buffer.from(
	'9551397153de34cc344549f724c3c448f0a61a96e05b700213f1d05cb6f81785d8b28523a19cfb0c65df3d484127c3486772ebcc1f6df452c76e51ec156fd488240bffc743170d943d764622e2ccf79518dbd54d322bdb88b398fc17545fb975eb8f4fa284ecdab825a3cb8245bae7dd5e8cb53a675f3aaa5cbced903145f4a5830a272d41474e42218fac332319d9bb792b3594bb2f0112824823da341a1eeb170b1871bb0971a4034c0038e0db2f3aaf0a53a1ae9b252ed01cfb17a667bd446b98f801d633beab6c215b6a7c82bcc04b0515f8b47e50d0a86325895c0877ab0ec1bf5071130f31fad5c1384bda7f57e829e849db57a08bc320ee0e59a5d202c07430ed8d1a7c0c1ce58f9263ed909f8135fede90154cece08ee79b76f05ae1309ced4cf120a555ba94a96aa23d61b8ee6896f01eef655291269686c96cc9a13248a13a3870a10c6eb6f836a1f7b93eb4355f9828546dd7487c6e69248d349cc7123320b7afa3b480dfd2fe9e27cbfedbbb192802d2a654a60fbfed7c87e7e6a586e0b8ec30df4bc622e797220626268fc11700c4b62406000718e7a11d38b319a3d5728e8c41ad0f2bb6085129e066ab3d92df365326106a28ea546183f891eab0d6d24838b99a982417a4e91b3f27a92dee29e06b5baad2fcb7b1cd56ba0a546b44e07f281a1420d0f4e7861b0a7ae56d2b71989086420409ad2dc24523b02ff61cbc8f189a28c3e0b82fd4063b9bf6c7f6b5dbe8d47cf96ba6c4d3f3b9debd0705b5a7bcccdd46c8f7842f83e118d7dac74f2f722426391669eba4fbadf0897c881ebe518fcf1b88e7805056c1b231a4bb307a22c1435ac297e2993348de689b10ce1bb73b26b554091af8a48b968aabff4a772065e9b14182fe06fb1ca8a653a367cc31439f7210e998795f32fb4eed2a01f435ce6d385b07d7140bd43a9ddb6e92f6c9460f0b26c10329e7f781de5fef6d131d54ed708a3847'
	'hex'
)
application	= Buffer.from('Detox test')

<-! lib.ready
test('Core', (t) !->
	generated_seed	= lib.generate_seed()
	t.ok(generated_seed instanceof Uint8Array, 'Seed is Uint8Array')
	t.equal(generated_seed.length, 32, 'Seed length is 32 bytes')

	bootstrap_node_seed		= new Uint8Array(32)
	bootstrap_node_id		= Buffer.from(detox-crypto.create_keypair(bootstrap_node_seed).ed25519.public).toString('hex')
	bootstrap_node_info		= "#bootstrap_node_id:#bootstrap_address:#bootstrap_port"

	node_1_real_seed		= new Uint8Array(32)
		..set([1, 1])
	node_1_real_public_key	= detox-crypto.create_keypair(node_1_real_seed).ed25519.public
	node_1_secret			= Buffer.from('c2fd7c6349f0bb25ed28', 'hex')
	node_3_real_seed		= new Uint8Array(32)
		..set([3, 1])
	node_3_real_public_key	= detox-crypto.create_keypair(node_3_real_seed).ed25519.public

	nodes	= []

	wait_for	= NUMBER_OF_NODES
	options		=
		timeouts				:
			STATE_UPDATE_INTERVAL				: 2
			GET_MORE_AWARE_OF_NODES_INTERVAL	: 2
			ROUTING_PATH_SEGMENT_TIMEOUT		: 30
			LAST_USED_TIMEOUT					: 15
			ANNOUNCE_INTERVAL					: 5
			RANDOM_LOOKUPS_INTERVAL				: 100
		connected_nodes_limit	: 30
		lookup_number			: 3
	promise		= Promise.resolve()
	for let i from 0 til NUMBER_OF_NODES
		promise		:= promise.then ->
			new Promise (resolve) !->
				dht_seed	= new Uint8Array(32)
					..set([i % 255, (i - i % 255) / 255])
				if i == 0
					instance	= lib.Core([], [], 10, 20, Object.assign({}, options, {dht_keypair_seed : dht_seed, connected_nodes_limit : NUMBER_OF_NODES}))
					instance.start_bootstrap_node(bootstrap_node_seed, bootstrap_ip, bootstrap_port, bootstrap_address)
				else
					instance	= lib.Core([bootstrap_node_info], [], 10, 2, Object.assign({dht_keypair_seed : dht_seed}, options))
				instance.once('ready', !->
					t.pass('Node ' + i + ' is ready, #' + (NUMBER_OF_NODES - wait_for + 1) + '/' + NUMBER_OF_NODES)

					if i == 2
						# Only check the first node after bootstrap
						t.same(instance.get_bootstrap_nodes(), [bootstrap_node_info], 'Bootstrap nodes are returned correctly')

						t.equal(instance.get_max_data_size(), 2 ** 16 - 2, 'Max data size returned correctly')

					--wait_for
					if !wait_for
						ready_callback()
				)
				nodes.push(instance)
				setTimeout(resolve, 100)

	!function destroy_nodes
		console.log 'Destroying nodes...'
		for node in nodes
			node.destroy()
		console.log 'Destroyed'
		t.end()

	!function ready_callback
		announcement_retry	= 3
		connection_retry	= 5
		node_1				= nodes[1]
		node_3				= nodes[3]
		node_1
			.once('announced', !->
				node_1.off('announcement_failed')
				t.pass('Announced successfully')

				node_1.on('introduction', (data) !->
					t.equal(data.application.subarray(0, application.length).join(','), application.join(','), 'Correct application on introduction')
					t.equal(data.secret.subarray(0, node_1_secret.length).join(','), node_1_secret.join(','), 'Correct secret on introduction')
					data.number_of_intermediate_nodes	= 1
				)
				node_3.once('connected', (, target_id) !->
					node_1.off('introduction')
					node_3.off('connection_failed')
					t.equal(target_id.join(','), node_1_real_public_key.join(','), 'Connected to intended node successfully')

					node_1.once('data', (, , received_command, received_data) !->
						t.equal(received_command, command, 'Received command correctly')
						t.equal(received_data.join(','), data.join(','), 'Received data correctly')

						destroy_nodes()
					)

					console.log 'Sending data...'
					node_3.send_to(node_3_real_public_key, node_1_real_public_key, command, data)
				)
				node_3.on('connection_failed', (, , reason) !->
					if connection_retry
						--connection_retry
						console.log 'Connection failed with code ' + reason + ', retry in 5s...'
						setTimeout (!->
							console.log 'Connecting...'
							node_3.connect_to(node_3_real_seed, node_1_real_public_key, application, node_1_secret, 1)
						), 5000
						return
					t.fail('Connection failed with code ' + reason)

					destroy_nodes()
				)

				console.log 'Preparing for connection (5s)...'
				# Hack to make sure at least one announcement reaches corresponding DHT node at this point
				setTimeout (!->
					console.log 'Connecting...'
					node_3.connect_to(node_3_real_seed, node_1_real_public_key, application, node_1_secret, 1)
				), 5000
			)
			.on('announcement_failed', (, reason) !->
				if announcement_retry
					--announcement_retry
					console.log 'Announcement failed with code ' + reason + ', retry...'
					return
				t.fail('Announcement failed with code ' + reason)

				destroy_nodes()
			)

		console.log 'Preparing for announcement (2s)...'
		setTimeout (!->
			console.log 'Announcing...'
			node_1.announce(node_1_real_seed, 3, 1)
		), 2000
)
