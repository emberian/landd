// A proof fabric (for example SIG) supplies verifyProofReceiptEnvelope's signature-verifying callback.
// The producer embeds the landd receipt in its signed payload.outcome.coneReceipt.
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { once } from 'node:events'
import { createHash } from 'node:crypto'
import { isDeepStrictEqual } from 'node:util'

function invoke(binary, args, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, { stdio: ['pipe', 'pipe', 'pipe'] })
    const stdout = [], stderr = []
    child.on('error', reject)
    child.stdin.on('error', reject)
    child.stdout.on('data', b => stdout.push(b))
    child.stderr.on('data', b => stderr.push(b))
    child.on('close', code => {
      if (code !== 0) return reject(new Error(Buffer.concat(stderr).toString() || 'landd failed'))
      try { resolve(JSON.parse(Buffer.concat(stdout))) } catch (error) { reject(error) }
    })
    child.stdin.end(input)
  })
}

export function createBridge({ binary = 'landd', repo, config, authenticate, validObligation, database, leadPrincipal }) {
  const station = ['--repo', repo, '--config', config]
  const workers = new Map()
  function podWorker(principal) {
    if (workers.has(principal)) return workers.get(principal)
    const child = spawn(binary, ['pod-step', '--stream', '--database', database, '--lead', leadPrincipal, '--principal', principal],
      { stdio: ['pipe', 'pipe', 'inherit'] })
    const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]()
    const closed = once(child, 'close')
    closed.catch(() => {})
    child.stdin.on('error', () => {})
    let tail = Promise.resolve()
    const worker = {
      async request(body) {
        const pending = tail.then(async () => {
          await new Promise((resolve, reject) => child.stdin.write(JSON.stringify(body) + '\n', err => err ? reject(err) : resolve()))
          const line = await lines.next()
          if (line.done) throw new Error('pod worker closed')
          const reply = JSON.parse(line.value)
          if (!reply.ok) throw new Error(reply.reason)
          return reply.task
        })
        tail = pending.catch(() => {})
        return pending
      },
      async close() { await tail; child.stdin.end(); await closed },
    }
    workers.set(principal, worker)
    closed.finally(() => workers.delete(principal)).catch(() => {})
    return worker
  }
  return {
    async close() { await Promise.all(Array.from(workers.values(), w => w.close())) },
    async verifyEnvelope(envelope, obligation) {
      try {
        if (!validObligation(obligation)) return { ok: false, reason: 'invalid-obligation' }
        const payload = envelope.payload
        const previous = payload.obligation
        const trusted = await authenticate(envelope, previous)
        if (trusted?.ok !== true || payload.status !== 'passed') return { ok: false, reason: 'untrusted-receipt' }
        if (obligation.reusePolicy === 'never' || !obligation.context || !previous.context) return { ok: false, reason: 'policy-change' }
        // SIG validates the current obligation. Only its tree/base may move.
        const policy = ({ key, context: { sourceTree, proofBase, ...context }, ...body }) => ({ ...body, context })
        if (!isDeepStrictEqual(policy(previous), policy(obligation))) return { ok: false, reason: 'policy-change' }
        const evidence = payload.outcome?.coneReceipt
        const receipt = evidence?.cone_attestation ?? evidence
        if (!receipt || receipt.judge_name !== obligation.targetId || receipt.tree_oid !== previous.context.sourceTree)
          return { ok: false, reason: 'receipt-binding' }
        const input = JSON.stringify(evidence)
        const pin = createHash('sha256').update(input).digest('hex')
        return await invoke(binary, ['verify-envelope', ...station, '--tree', obligation.context.sourceTree, '--trusted-sha256', pin], input)
      } catch (error) { return { ok: false, reason: error.message } }
    },
    // Receipt files belong to the operator's authenticated evidence store.
    trainStep(lanes, { receipts = [], apply = false } = {}) {
      return invoke(binary, ['train-step', ...station, ...receipts.flatMap(p => ['--receipt', p]), ...(apply ? ['--apply'] : []), '--', ...lanes])
    },
    // principal is supplied by the authenticated host session.
    podStep(principal, pod, task, action) {
      return podWorker(principal).request({ pod, task, action })
    },
  }
}
