/**
 * Emit the exact request body the console's multi-machine form produces.
 *
 * The Python side cross-checks that this JSON is accepted by the live FastAPI
 * schema, so the form and the endpoint cannot drift apart.
 */
import { deploymentPayload } from '../../src/lib/deployment.js'

const form = { client_count: 2, authority_count: 2, aggregator_count: 2,
  authority_threshold: 2, aggregator_threshold: 2, deployment: 'lan' }
const hosts = {
  authority1: { host: '192.168.1.10', machine: 'A' },
  authority2: { host: '192.168.1.11', machine: 'A' },
  aggregator1: { host: '192.168.1.10', machine: 'A' },
  aggregator2: { host: '192.168.1.12', machine: 'B' },
  client1: { host: '192.168.1.10', machine: 'A' },
  client2: { host: '192.168.1.12', machine: 'B' },
}
process.stdout.write(JSON.stringify(deploymentPayload({ ...form, hosts })))
