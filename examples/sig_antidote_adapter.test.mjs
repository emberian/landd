import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { createHmac, createHash } from 'node:crypto'
import { setTimeout as delay } from 'node:timers/promises'
import { createAdapter } from './sig_antidote_adapter.mjs'

const exec = promisify(execFile)
const binary = process.env.LANDD_BIN || 'landd'
const run = async (cmd, args, options) => (await exec(cmd, args, options)).stdout.trim()
const text = n => `export const n = ${n};\n`
const gate = `const vm=require('vm'),fs=require('fs'),p=require('path');
const mod=file=>new vm.SourceTextModule(fs.readFileSync(file,'utf8'),{identifier:file});
(async()=>{const m=mod(process.argv[1]);await m.link((s,r)=>mod(p.resolve(p.dirname(r.identifier),s)));await m.evaluate()})().catch(e=>{console.error(e);process.exitCode=1})`

test('eight sibling branches, transitive invalidation, binary isolation and durable Done', async t => {
  const root = await mkdtemp(join(tmpdir(), 'landd-antidote-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const repo = join(root, 'objects.git'), dest = join(root, 'dest.git'), config = join(root, 'land.toml')
  const env = { ...process.env, GIT_AUTHOR_NAME: 'Builder', GIT_COMMITTER_NAME: 'Builder',
    GIT_AUTHOR_EMAIL: 'builder@example.org', GIT_COMMITTER_EMAIL: 'builder@example.org' }
  const git = (args, extra) => run('git', ['-C', repo, ...args], { env: { ...env, ...extra } })
  await run('git', ['init', '--bare', '-b', 'main', repo])
  await run('git', ['init', '--bare', '-b', 'main', dest])
  await git(['remote', 'add', 'origin', dest])
  // Each builder owns an index. All eight write immutable objects to the same repo.
  async function commit(branch, base, files) {
    const index = { GIT_INDEX_FILE: join(root, branch + '.idx') }
    if (base) await git(['read-tree', base], index)
    for (const [path, body] of Object.entries(files)) {
      const source = join(root, branch + '-' + path)
      await writeFile(source, body)
      const blob = await git(['hash-object', '-w', source])
      await git(['update-index', '--add', '--cacheinfo', '100644', blob, path], index)
    }
    const tree = await git(['write-tree'], index)
    const oid = await git(['commit-tree', tree, ...(base ? ['-p', base] : []), '-m', branch])
    await git(['update-ref', 'refs/heads/' + branch, oid])
    return oid
  }
  const base = await commit('main', null, { 'd.ts': text(1), 'bridge.ts': "export {n} from './d.ts'", 'gate7.ts': "import {n} from './bridge.ts'; if(n < 0) throw Error('bad')",
    ...Object.fromEntries([2,3,4,5,6,8].map(i => [`gate${i}.ts`, text(0)])) })
  await git(['push', 'origin', 'main'])
  const edits = [{ 'd.ts': text(2) }, ...[2,3,4,5,6].map(i => ({ [`gate${i}.ts`]: text(i) })),
    { 'gate7.ts': "import {n} from './bridge.ts'; if(n !== 1) throw Error('transitive change')" }, { 'gate8.ts': "throw Error('C8')" }]
  await Promise.all(edits.map((files,i) => commit('C'+(i+1), base, files)))
  const rules = join(root, 'rules.toml')
  await writeFile(rules, '[imports]\ntests=["gate*.ts"]\nalways=[]\n')
  await writeFile(config, `cache_dir=${JSON.stringify(join(root,'state'))}\ncone_source="imports"\nrules=${JSON.stringify(rules)}\nisolation="none"\nenv_allow=["PATH"]\ntest_command=${JSON.stringify(['node','--experimental-vm-modules','-e',gate,'{path}'])}\n`)
  const station = ['--repo', repo, '--config', config]
  const sign = payload => createHmac('sha256', 'fixture signer').update(JSON.stringify(payload)).digest('hex')
  const adapter = createAdapter({ binary, config, repo, leadPrincipal: 'lead', database: join(root,'pod.db'),
    validObligation: o => o.key === createHash('sha256').update(JSON.stringify(o.context)).digest('hex'),
    authenticate: (e, o) => ({ok:e.signature === sign(e.payload) && e.payload.obligation.key===o.key}) })
  t.after(() => adapter.close())
  const receipts = [], issued = []
  for (const i of [2,3,4,5,6,7]) {
    const output = await run(binary, ['judge-cone', ...station, '--rev', 'C'+i, '--unit', `gate${i}.ts`])
    const receipt = JSON.parse(output)
    assert.equal(receipt.all_passed, true)
    const path = join(root, i+'.receipt')
    if (i === 3) {
      // OBB v7 writes wire version 1. Its receipt hash covers the compact signable JSON.
      const judge = {receipt_version:1,judge_name:receipt.judge_name,gate_sha256:createHash('sha256').update('gate').digest('hex'),
        repo_root:repo,base_sha:base,head_sha:await git(['rev-parse','C3']),tree_oid:receipt.tree_oid,clean_working_tree:true,
        changed_paths:['gate3.ts'],checked_at:'2026-11-23T00:00:00Z',all_passed:true,achieved_regime:'attested',kernel_verified:false,
        teeth_report:{total:0,bit_count:0,vacuous_count:0,invalid_count:0,positive_failed_count:0,all_bit:true,results:[]},evaluations:[]}
      const hash = s => createHash('sha256').update(s).digest('hex')
      const file = JSON.stringify({...judge,receipt_hash:hash(JSON.stringify(judge))})
      await writeFile(path,JSON.stringify({judge_receipt_json:file,judge_file_sha256:hash(file),obb_gate_sha256:judge.gate_sha256,cone_attestation:receipt}))
    } else await writeFile(path, output)
    receipts.push(path); issued[i] = receipt
  }
  assert.deepEqual(Object.keys(issued[7].cone_blobs), ['bridge.ts','d.ts','gate7.ts'])
  await git(['push','origin','C1:main'])
  const good = ['C2','C3','C4','C5','C6']
  const preview = await adapter.trainStep(good, { receipts })
  assert.equal(preview.tally.candidate_units_run, 0)
  assert.equal(preview.tally.base_units_run, 0)
  assert.deepEqual(Object.keys(preview.tally.external_receipts),good.map(c=>'gate'+c.slice(1)+'.ts'))
  const report = await adapter.trainStep([...good,'C7','C8'], { receipts, apply:true })
  assert.deepEqual(report.outcomes.map(([,o]) => o.outcome), [...good.map(()=>'landed'),'declined','declined'])
  assert.ok(report.tally.evaluations > 1)
  assert.equal(report.tally.candidate_units_run,2)
  for (const c of good) await git(['merge-base','--is-ancestor',c,report.remote_head])
  const mergedTree = await git(['rev-parse', report.remote_head+'^{tree}'])
  const obligation = (i,tree) => {
    const context = {sourceTree:tree,proofBase:base,policyHash:'policy',environmentClass:'local',toolchain:{node:'fixture'}}
    return {key:createHash('sha256').update(JSON.stringify(context)).digest('hex'),context,targetId:`gate${i}.ts`,reusePolicy:'eligible',inputDigest:'declared'}
  }
  const envelope = i => {
    const payload={status:'passed',obligation:obligation(i,issued[i].tree_oid),outcome:{coneReceipt:issued[i]}}
    return {payload,signature:sign(payload)}
  }
  assert.equal((await adapter.verifyEnvelope(envelope(2),obligation(2,mergedTree))).ok,true)
  assert.equal((await adapter.verifyEnvelope(envelope(7),obligation(7,mergedTree))).ok,false)
  assert.equal((await adapter.verifyEnvelope({...envelope(2),signature:'wrong'},obligation(2,mergedTree))).ok,false)
  const pod=(principal,action)=>adapter.podStep(principal,'batch','build',action)
  await assert.rejects(pod('builder',{op:'create_pod',tasks:['build']}))
  await pod('lead',{op:'create_pod',tasks:['build','expired','canceled']})
  const stale=await adapter.podStep('builder','batch','expired',{op:'claim',lease_seconds:1})
  await adapter.podStep('lead','batch','canceled',{op:'cancel'})
  const claim=await pod('builder',{op:'claim',lease_seconds:2})
  await pod('builder',{op:'done',fencing_token:claim.fencing_token})
  await adapter.close()
  await delay(2100)
  const reclaimed=await adapter.podStep('peer','batch','expired',{op:'claim',lease_seconds:10})
  assert.ok(reclaimed.fencing_token > stale.fencing_token)
  await assert.rejects(adapter.podStep('builder','batch','expired',{op:'done',fencing_token:stale.fencing_token}))
  await assert.rejects(adapter.podStep('peer','batch','canceled',{op:'claim',lease_seconds:10}))
  assert.equal((await pod('lead',{op:'inspect'})).state,'done')
  await assert.rejects(pod('builder',{op:'claim',lease_seconds:2}))
  await assert.rejects(pod('builder',{op:'verify'}))
  assert.equal((await pod('lead',{op:'verify'})).state,'verified')
  await assert.rejects(pod('builder',{op:'claim',lease_seconds:2}))
  await assert.rejects(pod('builder',{op:'reopen'}))
  await pod('lead',{op:'reopen'})
  const next=await pod('builder',{op:'claim',lease_seconds:10})
  assert.ok(next.fencing_token > claim.fencing_token)
  await assert.rejects(pod('builder',{op:'done',fencing_token:claim.fencing_token}))
  t.diagnostic(JSON.stringify({preview:preview.tally, mixed:report.tally}))
})
