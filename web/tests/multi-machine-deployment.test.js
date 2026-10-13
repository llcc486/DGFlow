/**
 * Multi-machine deployment from entered IP addresses.
 *
 * The console must keep the single-machine option intact, describe the
 * multi-machine layout as one address per node, and refuse addresses that cannot
 * work before the backend is asked to mint identities for them.
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import {
  DEFAULT_TOPOLOGY, MACHINE_GROUPS, deployedHosts, deploymentPayload, deploymentPayloadError,
  lanHosts, lanHostsError, sameLanHosts, topologyNodeNames, usedMachines, validHost,
} from '../src/lib/deployment.js'

const TOPOLOGY = { client_count: 2, authority_count: 2, aggregator_count: 2,
  authority_threshold: 2, aggregator_threshold: 2 }

const spread = {
  client1: { host: '192.168.1.11', machine: 'A' },
  client2: { host: '192.168.1.11', machine: 'A' },
  authority1: { host: '192.168.1.12', machine: 'B' },
  authority2: { host: '192.168.1.13', machine: 'C' },
  aggregator1: { host: '192.168.1.12', machine: 'B' },
  aggregator2: { host: '192.168.1.13', machine: 'C' },
}

test('node names follow the configured role counts', () => {
  assert.deepEqual(topologyNodeNames(2, 2, 2), ['authority1', 'authority2', 'aggregator1', 'aggregator2', 'client1', 'client2'])
  assert.equal(topologyNodeNames(6, 3, 4).length, 13)
  // Counts outside the allowed ranges must not invent node names.
  assert.deepEqual(topologyNodeNames(1, 2, 2), ['authority1', 'authority2', 'aggregator1', 'aggregator2'])
})

test('single-machine deployments keep the existing request shape plus an explicit mode', () => {
  const payload = deploymentPayload({ ...TOPOLOGY, client_count: 9 })
  assert.deepEqual(payload, { ...TOPOLOGY, client_count: 9, deployment: 'single_host' })
  assert.equal(payload.hosts, undefined, 'a single-machine request must not carry addresses')
  assert.equal(deploymentPayloadError({ ...TOPOLOGY }), '')
})

test('multi-machine deployments carry one address per configured node', () => {
  const payload = deploymentPayload({ ...TOPOLOGY, deployment: 'lan', hosts: spread })
  assert.equal(payload.deployment, 'lan')
  assert.equal(Object.keys(payload.hosts).length, 6)
  assert.deepEqual(payload.hosts.client1, { host: '192.168.1.11', machine: 'A' })
  assert.deepEqual(payload.hosts.authority2, { host: '192.168.1.13', machine: 'C' })
  // The five topology fields still travel, so the backend can size the cluster.
  for (const field of ['client_count', 'authority_count', 'aggregator_count', 'authority_threshold', 'aggregator_threshold']) {
    assert.equal(payload[field], TOPOLOGY[field])
  }
})

test('entered addresses are trimmed and unknown groups fall back to the coordinator', () => {
  const hosts = lanHosts(TOPOLOGY, { client1: { host: '  10.0.0.5  ', machine: 'ZZ' } })
  assert.equal(hosts.client1.host, '10.0.0.5')
  assert.equal(hosts.client1.machine, 'A')
})

test('addresses are accepted as IPv4 literals or host names only', () => {
  for (const host of ['192.168.1.10', '10.0.0.1', 'dgflow-node-2', 'node.lab.local', '255.255.255.255']) {
    assert.equal(validHost(host), true, host)
  }
  for (const host of ['', '   ', 'https://192.168.1.10', '192.168.1.10:9301', '0.0.0.0',
    '999.1.1.1', '192.168.1', '192.168.1.1.1', '-bad', 'bad-', 'a..b', 'host/path', 'http://x']) {
    assert.equal(validHost(host), false, host)
  }
})

test('every node must have a usable address and one machine must coordinate', () => {
  assert.equal(lanHostsError(spread), '')
  const blank = { ...spread, authority1: { host: '', machine: 'B' } }
  assert.match(lanHostsError(blank), /authority1/)
  const url = { ...spread, client2: { host: 'https://192.168.1.11', machine: 'A' } }
  assert.match(lanHostsError(url), /client2/)
  const noCoordinator = Object.fromEntries(Object.entries(spread).map(([name, entry]) => [name, { ...entry, machine: 'B' }]))
  assert.match(lanHostsError(noCoordinator), /A 组/)
  // A topology with no nodes yet is a configuration problem, not a valid layout.
  assert.match(lanHostsError({}, []), /数量/)
})

test('only machines that own a node are offered for provisioning', () => {
  assert.deepEqual(usedMachines(spread), ['A', 'B', 'C'])
  assert.equal(MACHINE_GROUPS.length, 164)
  assert.equal(MACHINE_GROUPS[26], 'AA')
  assert.equal(MACHINE_GROUPS.at(-1), 'FH')
  assert.deepEqual(usedMachines({ client1: { host: '10.0.0.1', machine: 'A' } }), ['A'])
  assert.deepEqual(usedMachines({}), [])
})

test('saved addresses are recognised so an unchanged layout can be re-applied', () => {
  assert.equal(sameLanHosts(spread, { ...spread }), true)
  assert.equal(sameLanHosts(spread, { ...spread, client1: { host: '10.0.0.9', machine: 'A' } }), false)
  assert.equal(sameLanHosts(spread, { ...spread, client1: { host: '192.168.1.11', machine: 'B' } }), false)
  assert.equal(sameLanHosts({}, {}), false)
  assert.equal(sameLanHosts(spread, { client1: spread.client1 }), false)
})

test('the form opens on the addresses a running LAN deployment already uses', () => {
  const status = { deployment: 'lan', nodes: [
    { id: 'client1', host: 'https://192.168.1.11:9301' },
    { id: 'authority1', host: 'https://192.168.1.12:9101' },
    { id: 'aggregator1', host: 'https://192.168.1.13:9201' },
  ] }
  const found = deployedHosts(status, { ...TOPOLOGY, client_count: 2, authority_count: 2, aggregator_count: 2 })
  assert.equal(found.client1.host, '192.168.1.11')
  assert.equal(found.authority1.host, '192.168.1.12')
  assert.equal(found.aggregator1.host, '192.168.1.13')
  // Nodes the running deployment never mentioned stay blank rather than invented.
  assert.equal(found.client2.host, '')
})

test('a single-machine status still yields only the addresses it knows', () => {
  const status = { deployment: 'single_host', nodes: [{ id: 'client1', host: 'https://127.0.0.1:9301' }] }
  const found = deployedHosts(status, { ...TOPOLOGY, client_count: 2, authority_count: 2, aggregator_count: 2 })
  assert.equal(found.client1.host, '127.0.0.1')
  assert.equal(found.authority1.host, '')
})

test('the payload error surfaces the address problem before any request', () => {
  assert.equal(deploymentPayloadError({ ...TOPOLOGY, deployment: 'lan', hosts: spread }), '')
  assert.match(deploymentPayloadError({ ...TOPOLOGY, deployment: 'lan',
    hosts: { ...spread, aggregator2: { host: 'not a host', machine: 'C' } } }), /aggregator2/)
  // Topology errors still take precedence.
  assert.match(deploymentPayloadError({ ...DEFAULT_TOPOLOGY, client_count: 1, deployment: 'lan', hosts: spread }), /2–100/)
})
