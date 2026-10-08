"""Compare the frozen protocol and current code on the same real crypto inputs.

Run from the repository root, for example:
  .venv/Scripts/python.exe scripts/benchmark_crypto.py --dimensions 32 650 --repeats 3
  .venv/Scripts/python.exe scripts/benchmark_crypto.py --baseline-dir tmp/acceleration-baseline --proof-suite compact_norm_v1

Synthetic plaintexts and fresh cryptographic randomness are used only in memory.
The JSON contains timings, dimensions and code hashes, never keys or plaintexts.
Cold clears public/decoded-element caches before every sample. Warm pre-runs the
exact operation, so repeated aggregate GT encodings can hit the decoding cache;
it must not be presented as a fresh-round latency measurement.
"""
import argparse
import hashlib
import importlib.metadata
import json
import platform
import statistics
import subprocess
import sys
import time
import types
from pathlib import Path

from dgfl.experiments.runner import implementation_evidence
from dgfl.transport.binary import packb

ROOT = Path(__file__).resolve().parents[1]
FROZEN_RELEASE = '34f8602d22c934a2acd3dcb2a36355a20dc5aeb2'
STAGES=('dkg_all_clients','enroll_one_client','encrypt_one_client','prove_one_client',
        'verify_one_client','validate_inner_product_one_client','partial_decrypt_one_cloud','combine_two_clouds')


def snapshot_modules(sources, destination, package_name, wire_source=None):
    package = types.ModuleType(package_name)
    package.__path__ = [str(destination)]
    sys.modules[package_name] = package
    hashes = {}
    destination.mkdir(parents=True, exist_ok=True)
    # Freeze helpers too: lazy relative imports must use the captured sources,
    # rather than a compact-proof module edited during a benchmark run.
    for name,raw in sources.items():
        relative = f'src/dgfl/crypto/{name}.py'
        hashes[relative] = hashlib.sha256(raw).hexdigest()
        source_path = destination/f'{name}.py'
        source_path.write_bytes(raw)
    wire=None
    if wire_source is not None:
        source_path=destination/'_wire_codec.py'
        source_path.write_bytes(wire_source)
        hashes['src/dgfl/transport/binary.py']=hashlib.sha256(wire_source).hexdigest()
        wire=types.ModuleType(package_name+'._wire_codec')
        wire.__file__=str(source_path); wire.__package__=package_name
        sys.modules[wire.__name__]=wire
        exec(compile(wire_source,str(source_path),'exec'),wire.__dict__)
    # Eagerly initialize known proof helpers. Their packb globals then refer to
    # this snapshot's codec even though production imports use dgfl.transport.
    for name in ('backend','ipa','compact','protocol'):
        if name not in sources:
            continue
        raw=sources[name]
        source_path=destination/f'{name}.py'
        module_name = package_name+'.'+name
        module = types.ModuleType(module_name)
        module.__package__ = package_name
        module.__file__ = str(source_path)
        sys.modules[module_name] = module
        setattr(package, name, module)
        exec(compile(raw, str(source_path), 'exec'), module.__dict__)
        if wire is not None and 'packb' in module.__dict__:
            module.packb=wire.packb
    return package.backend, package.protocol, hashes


def frozen_modules(ref, destination):
    sources = {name:subprocess.check_output(
        ['git', 'show', f'{ref}:src/dgfl/crypto/{name}.py'], cwd=ROOT)
        for name in ('backend', 'protocol')}
    wire_source=subprocess.check_output(['git','show',f'{ref}:src/dgfl/transport/binary.py'],cwd=ROOT)
    return snapshot_modules(sources,destination,'_dgfl_crypto_benchmark_baseline',wire_source)


def directory_sources(directory):
    directory=Path(directory).resolve()
    candidates=(directory/'src'/'dgfl'/'crypto',directory/'crypto',directory)
    source=next((path for path in candidates if (path/'backend.py').is_file() and (path/'protocol.py').is_file()),None)
    if source is None:
        raise ValueError('baseline directory must contain backend.py and protocol.py')
    return {path.stem:path.read_bytes() for path in sorted(source.glob('*.py'))}


def directory_wire_source(directory):
    directory=Path(directory).resolve()
    candidates=(directory/'src'/'dgfl'/'transport'/'binary.py',
                directory/'transport'/'binary.py',directory.parent/'transport'/'binary.py')
    source=next((path for path in candidates if path.is_file()),None)
    if source is None:
        raise ValueError('baseline snapshot must also include dgfl/transport/binary.py')
    return source.read_bytes()


def clear_caches(backend):
    prefix=backend.__package__+'.'
    for name,module in list(sys.modules.items()):
        if name.startswith(prefix):
            for function in list(vars(module).values()):
                if hasattr(function,'cache_clear'):
                    function.cache_clear()


def make_authorities(protocol, clients, dimension, epoch):
    nodes = [protocol.Authority(i, [1, 2, 3], clients, dimension, 2, epoch)
             for i in (1, 2, 3)]
    commitments = {node.node_id:node.commitments() for node in nodes}
    for receiver in nodes:
        receiver.set_commitments(commitments)
        for dealer in nodes:
            receiver.receive_share(dealer.node_id, dealer.share_for(receiver.node_id))
    for node in nodes:
        node.finalize()
    return nodes


def timed_pair(operations, backends, repeats, cache_mode):
    samples = {name:[] for name in operations}
    cpu_samples={name:[] for name in operations}
    for repeat in range(repeats):
        # Alternate execution order to reduce systematic first/second bias.
        names = list(operations)
        if repeat % 2:
            names.reverse()
        for name in names:
            clear_caches(backends[name])
            if cache_mode == 'warm':
                operations[name]()
            start = time.perf_counter()
            cpu_start=time.process_time()
            operations[name]()
            samples[name].append(time.perf_counter()-start)
            cpu_samples[name].append(time.process_time()-cpu_start)
    result = {name:{'samples_seconds':values,
                    'median_seconds':statistics.median(values),
                    'samples_cpu_seconds':cpu_samples[name],
                    'median_cpu_seconds':statistics.median(cpu_samples[name])}
              for name, values in samples.items()}
    result['baseline_over_current_median'] = (
        result['baseline']['median_seconds']/result['current']['median_seconds'])
    return result


def benchmark_dimension(baseline, current, dimension, clients, bits, repeats,
                        proof_suite='legacy',verification='deterministic',block_size=128,
                        stages=STAGES,cache_modes=('cold','warm')):
    old_b, old_p = baseline
    new_b, new_p = current
    backends = {'baseline':old_b, 'current':new_b}
    protocols = {'baseline':old_p, 'current':new_p}
    client_ids = [f'benchmark-client-{i}' for i in range(clients)]
    epoch = f'benchmark-{dimension}'
    legacy_ctx = {'task_id':'crypto-benchmark', 'round_id':1, 'key_epoch':epoch,
           'model_hash':'ab'*32, 'bits':bits, 'scale':16, 'dimension':dimension}
    contexts={'baseline':legacy_ctx,'current':dict(legacy_ctx)}
    if proof_suite!='legacy':
        contexts['current'].update(proof_suite=proof_suite,proof_block_size=block_size)
    offset = 1 << (bits-1)
    vectors = {cid:[((j*17+i*7+3) % (2*offset))-offset for j in range(dimension)]
               for i, cid in enumerate(client_ids)}
    reference = [((j*13+5) % (2*offset))-offset for j in range(dimension)]
    nodes = make_authorities(old_p, client_ids, dimension, epoch)
    enrollment = {cid:[n.client_share(cid) for n in nodes] for cid in client_ids}
    keys = {cid:old_p.recover_client_key(enrollment[cid], 2) for cid in client_ids}
    packets_by_version={name:{cid:protocol.encrypt(contexts[name],cid,vectors[cid],keys[cid])
                             for cid in client_ids} for name,protocol in protocols.items()}
    cid = client_ids[0]
    key,values=keys[cid],vectors[cid]
    norm = sum(v*v for v in values)
    proofs={name:protocol.prove(contexts[name],cid,values,key,packets_by_version[name][cid]['ciphertext'])
            for name,protocol in protocols.items()}
    validation_keys = [n.validation_key(cid, reference) for n in nodes]
    manifest = 'crypto-benchmark-approved'
    aggregate_keys = {'baseline':{cloud:[n.aggregate_key(client_ids, cloud, 2, manifest) for n in nodes]
                                 for cloud in (1, 2)}}
    aggregate_verification_material=None
    if hasattr(new_p,'_prove_aggregate_verification'):
        # The same enrolled scalar fixture is reused, while the new DKGen
        # creates its own blinded polynomial commitments and correctness proof.
        current_nodes=[]
        for node in nodes:
            clone=new_p.Authority.__new__(new_p.Authority)
            clone.__dict__.update(vars(node))
            clone._aggregate={}; clone._aggregate_verifications={}
            clone._transcript={str(n.node_id):n.commitments() for n in nodes}
            current_nodes.append(clone)
        aggregate_keys['current']={cloud:[n.aggregate_key(client_ids,cloud,2,manifest,context=contexts['current'])
                                        for n in current_nodes] for cloud in (1,2)}
        aggregate_verification_material={
            'materials':[m['verification'] for rows in aggregate_keys['current'].values() for m in rows],
            'commitments':current_nodes[0]._transcript}
    else:
        aggregate_keys['current']=aggregate_keys['baseline']
    parts_by_version={'baseline':[old_p.partial_decrypt(legacy_ctx,packets_by_version['baseline'],
                           aggregate_keys['baseline'][cloud],2,cloud,manifest) for cloud in (1,2)]}
    parts_by_version['current']=[new_p.partial_decrypt(contexts['current'],packets_by_version['current'],
                                 aggregate_keys['current'][cloud],2,cloud,manifest) for cloud in (1,2)]
    print(f'dimension={dimension} fixture ready; checking proof and integer outputs',flush=True)
    expected = [sum(vector[j] for vector in vectors.values()) for j in range(dimension)]

    # Independent correctness assertions use one identical fixture in both
    # implementations. Randomized proof encodings are not expected to match.
    def verify(name,ctx,ciphertext,claimed_norm,proof):
        if name=='baseline':
            return old_p.verify(ctx,cid,ciphertext,claimed_norm,proof,key['public'])
        return new_p.verify(ctx,cid,ciphertext,claimed_norm,proof,key['public'],verification=verification)

    legacy_packet=packets_by_version['baseline'][cid]
    def combine(name):
        options=({'verification_materials':aggregate_verification_material,'packets':packets_by_version[name]}
                 if name=='current' and aggregate_verification_material is not None else {})
        return protocols[name].combine(contexts[name],parts_by_version[name],2,clients,manifest,**options)

    for name,protocol in protocols.items():
        ctx=contexts[name]; packets=packets_by_version[name]; packet=packets[cid]; proof=proofs[name]
        assert protocol.recover_client_key(enrollment[cid], 2) == key
        assert protocol.encrypt(ctx, cid, values, key) == packet
        assert verify(name,ctx,packet['ciphertext'],norm,proof), f'{name}: generated proof was rejected'
        assert not verify(name,ctx,packet['ciphertext'],norm+1,proof)
        assert protocol.validate_inner_product(ctx, packet['ciphertext'], reference,
                                               validation_keys, 2) == sum(x*y for x,y in zip(values,reference))
        # Aggregate correctness is checked against independently constructed
        # integer sums. Re-running the same partial() to compare to itself adds
        # cost without an independent oracle.
        assert combine(name) == expected

    # The legacy fixture must remain wire compatible in the new implementation.
    assert new_p.encrypt(legacy_ctx,cid,values,key)==legacy_packet
    assert verify('current',legacy_ctx,legacy_packet['ciphertext'],norm,proofs['baseline'])
    if proof_suite=='legacy':
        assert old_p.verify(legacy_ctx,cid,legacy_packet['ciphertext'],norm,proofs['current'],key['public'])

    def operations(name,protocol):
        ctx=contexts[name]; packets=packets_by_version[name]; packet=packets[cid]
        proof=proofs[name]
        return {
            'dkg_all_clients':lambda:make_authorities(protocol, client_ids, dimension, epoch),
            'enroll_one_client':lambda:protocol.recover_client_key(enrollment[cid], 2),
            'encrypt_one_client':lambda:protocol.encrypt(ctx, cid, values, key),
            'prove_one_client':lambda:protocol.prove(ctx, cid, values, key, packet['ciphertext']),
            'verify_one_client':lambda:verify(name,ctx,packet['ciphertext'],norm,proof),
            'validate_inner_product_one_client':lambda:protocol.validate_inner_product(
                ctx, packet['ciphertext'], reference, validation_keys, 2),
            'partial_decrypt_one_cloud':lambda:protocol.partial_decrypt(
                ctx, packets, aggregate_keys[name][1], 2, 1, manifest),
            'combine_two_clouds':lambda:combine(name),
        }

    operations_by_version = {name:operations(name,protocol) for name, protocol in protocols.items()}
    measurements = {}
    for stage in stages:
        pair = {name:ops[stage] for name, ops in operations_by_version.items()}
        measurements[stage] = {mode:timed_pair(pair, backends, repeats, mode)
                               for mode in cache_modes}
        print(f'dimension={dimension} stage={stage} complete', flush=True)
    return {'dimension':dimension, 'clients':clients, 'bits':bits, 'authorities':3,
            'current_proof_suite':proof_suite,'current_verification':verification,
            'proof_block_size':block_size,
            'proof_bytes':{name:len(packb(proof)) for name,proof in proofs.items()},
            'authority_threshold':2, 'aggregate_parts':2,
            'output_equivalence':{'enrollment':True, 'ciphertext':True,
                                  'ciphertext_scope':'legacy context wire compatibility; compact context has its own domain',
                                  'legacy_proof_verified_by_current':True,
                                  'current_proof_verified_by_baseline':proof_suite=='legacy',
                                  'modified_norm_rejected':True,
                                  'inner_product':True,
                                  'partial_ciphertexts':'legacy parts consumed by current; compact parts use their own context',
                                  'aggregate_plaintext':True},
            'stages':measurements}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dimensions', type=int, nargs='+', default=[32])
    parser.add_argument('--clients', type=int, default=2)
    parser.add_argument('--bits', type=int, default=8)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--baseline-ref', default=FROZEN_RELEASE)
    parser.add_argument('--baseline-dir',type=Path,
                        help='local frozen sources; accepted layouts are repo/src/dgfl/crypto or crypto directory')
    parser.add_argument('--proof-suite',choices=('legacy','compact_range_v1','compact_norm_v1'),default='legacy')
    parser.add_argument('--verification',choices=('deterministic','randomized'),default='deterministic')
    parser.add_argument('--block-size',type=int,default=128)
    parser.add_argument('--stages',nargs='+',choices=STAGES,default=list(STAGES))
    parser.add_argument('--cache-modes',nargs='+',choices=('cold','warm'),default=['cold','warm'])
    parser.add_argument('--output', type=Path, default=ROOT/'tmp'/'benchmark-crypto.json')
    args = parser.parse_args()
    if sys.flags.optimize:
        parser.error('optimized Python disables benchmark correctness assertions; run without -O')
    if (any(not 1 <= d <= 20000 for d in args.dimensions) or not 2 <= args.clients <= 32
            or not 2 <= args.bits <= 16 or not 1 <= args.repeats <= 100
            or not 1<=args.block_size<=1024):
        parser.error('unsupported dimensions, client count, bits, or repeats')
    output = args.output.resolve()
    script_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    snapshot = output.parent/(output.stem+'-baseline')
    if args.baseline_dir is not None:
        baseline_commit=None
        old_b,old_p,baseline_hashes=snapshot_modules(directory_sources(args.baseline_dir),snapshot,
                                                    '_dgfl_crypto_benchmark_baseline',
                                                    directory_wire_source(args.baseline_dir))
    else:
        baseline_commit = subprocess.check_output(
            ['git','rev-parse','--verify',args.baseline_ref+'^{commit}'],cwd=ROOT,text=True).strip()
        old_b,old_p,baseline_hashes=frozen_modules(baseline_commit,snapshot)
    current_sources=directory_sources(ROOT)
    new_b, new_p, current_hashes = snapshot_modules(
        current_sources,output.parent/(output.stem+'-current'),'_dgfl_crypto_benchmark_current',
        directory_wire_source(ROOT))
    result = {'schema_version':2, 'kind':'synthetic_crypto_microbenchmark',
              'baseline_commit':baseline_commit, 'baseline_source_sha256':baseline_hashes,
              'baseline_source':'local_directory' if args.baseline_dir is not None else 'git_ref',
              'current_source_sha256':current_hashes,
              'native_extension_enabled':{'baseline':bool(getattr(old_b,'NATIVE_EXTENSION',False)),
                                          'current':bool(getattr(new_b,'NATIVE_EXTENSION',False))},
              'native':implementation_evidence()['native'],
              'script_sha256':script_hash,
              'crypto_package_version':importlib.metadata.version('py-arkworks-bls12381'),
              'python':sys.version, 'platform':platform.platform(), 'repeats':args.repeats,
              'measured_stages':args.stages,'cache_modes':args.cache_modes,
              'cache_semantics':{'cold':'clear Python memoized public/decoded caches in snapshotted crypto modules before each sample; native tables may persist',
                                 'warm':'pre-run identical operation after clear; GT values can hit decode cache'},
              'limitations':['same-process microbenchmark; excludes RPC, training and process contention',
                             'fresh DKG and proofs use nondeterministic cryptographic randomness',
                             'warm aggregate inputs are identical replays, not fresh FL rounds'],
              'results':[]}
    for dimension in args.dimensions:
        result['results'].append(benchmark_dimension((old_b,old_p),(new_b,new_p),dimension,
                                                     args.clients,args.bits,args.repeats,
                                                     args.proof_suite,args.verification,args.block_size,
                                                     args.stages,args.cache_modes))
        if hashlib.sha256(Path(__file__).read_bytes()).hexdigest()!=script_hash:
            raise RuntimeError('benchmark sources changed during execution; result not published')
        # Operations use the captured source modules, so continued development
        # cannot alter this run. Record differences explicitly instead of
        # incorrectly presenting captured measurements as final-source results.
        result['workspace_source_changes_after_snapshot']=[path for path,digest in current_hashes.items()
            if not (ROOT/path).is_file() or hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=digest]
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
        print(f'Completed dimension={dimension}; output={output}', flush=True)


if __name__ == '__main__':
    main()
