"""Benchmark pairwise-coprime key recovery on the 24 recommended GTLN sets.

Example: python benchmark.py --trials 100 --Cp 2 --Cg 2 --seed 20261012
All generated private coordinates are prime. The timed attacker does not
test primality. Key generation and evaluation are outside the attack timer.
"""
import argparse
from collections import Counter
import csv
from dataclasses import asdict
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import json
from math import gcd, prod
from pathlib import Path
import platform
import statistics
import sys
from time import perf_counter
from cf_attack import attack, modulus_multiple, pairwise_coprime
from key_generation import PARAMETERS, keygen, make_rng, is_prime


def evaluate(public, secret, par, result, Cp, Cg):
    """Ground truth is accessed only after the timed attack has finished."""
    top = sorted(secret.p)[-par.t:]
    lm = prod(top)
    om = (par.z-1)*sum(lm//p for p in top)
    if not (secret.g.bit_length() == par.G and secret.g >= 4*lm*lm
            and secret.g > 4*om*om):
        raise AssertionError('Generated modulus violates key-generation bounds')
    assert all(is_prime(p) for p in secret.p)
    ps, g, u = secret.p, secret.g, secret.u
    truth_in = secret in result.candidates
    out = dict(unique_exact=int(result.candidates == [secret]),
               truth_in_candidates=int(truth_in), candidate_count=len(result.candidates),
               ratios_exact=0, ratio_count=len(result.ratios),
               f_lo=None, f_hi=None, c=None, true_Fg=None, caps_cover_truth=0)
    for candidate in result.candidates:
        assert pairwise_coprime(candidate.p)
        assert all(par.z <= p < par.P for p in candidate.p)
        assert candidate.g > max(public) and 0 < candidate.u < candidate.g
        assert all((p*(ti+candidate.u)-1) % candidate.g == 0
                   for p,ti in zip(candidate.p,public))
    if len(result.ratios) != par.n-2:
        return out
    ks = [(p*(ti+u)-1)//g for p, ti in zip(ps, public)]
    ql, qh = Fraction(ks[result.lo], ps[result.lo]), Fraction(ks[result.hi], ps[result.hi])
    out['ratios_exact'] = int(all(Fraction(N,M) ==
        (Fraction(ks[i], ps[i])-ql)/(qh-ql) for i,(N,M) in result.ratios.items()))
    assert result.gamma_lo % ps[result.lo] == 0
    assert result.gamma_hi % ps[result.hi] == 0
    out['f_lo'], out['f_hi'] = result.gamma_lo//ps[result.lo], result.gamma_hi//ps[result.hi]
    true_g0 = modulus_multiple(public, ps)
    assert true_g0 % g == 0
    out['c'] = true_g0//g
    out['true_Fg'] = true_g0//(max(public)+1)
    out['caps_cover_truth'] = int(out['f_lo'] <= Cp and out['f_hi'] <= Cp and out['c'] <= Cg)
    if out['ratios_exact'] and out['caps_cover_truth'] and not truth_in:
        raise AssertionError('Conditional recovery theorem violated by implementation')
    assert result.endpoint_scans <= 2*Cp
    assert result.endpoint_pairs <= Cp*Cp
    assert result.modulus_scans <= result.integer_vectors*Cg
    return out


def percentile(xs, q):
    xs = sorted(xs)
    pos = (len(xs)-1)*q
    lo = int(pos); hi = min(lo+1, len(xs)-1)
    return xs[lo]+(xs[hi]-xs[lo])*(pos-lo)


def summarize(rows):
    times = [r['attack_s'] for r in rows]
    hist = lambda k: {str(v): c for v,c in sorted(Counter(r[k] for r in rows).items(), key=lambda x:str(x[0]))}
    return dict(trials=len(rows), unique_exact=sum(r['unique_exact'] for r in rows),
        truth_in_candidates=sum(r['truth_in_candidates'] for r in rows),
        no_candidate=sum(r['candidate_count']==0 for r in rows),
        ambiguous=sum(r['candidate_count']>1 for r in rows),
        wrong_unique=sum(r['candidate_count']==1 and not r['truth_in_candidates'] for r in rows),
        ratios_exact=sum(r['ratios_exact'] for r in rows),
        total_ratios=sum(r['ratio_count'] for r in rows),
        caps_cover_truth=sum(r['caps_cover_truth'] for r in rows),
        mean_s=statistics.mean(times), median_s=statistics.median(times),
        p95_s=percentile(times,.95), max_s=max(times),
        cf_mean_s=statistics.mean(r['cf_s'] for r in rows),
        endpoint_mean_s=statistics.mean(r['endpoint_s'] for r in rows),
        modulus_mean_s=statistics.mean(r['modulus_s'] for r in rows),
        keygen_mean_s=statistics.mean(r['keygen_s'] for r in rows),
        endpoint_scans_max=max(r['endpoint_scans'] for r in rows),
        endpoint_pairs_max=max(r['endpoint_pairs'] for r in rows),
        modulus_scans_max=max(r['modulus_scans'] for r in rows),
        f_lo=hist('f_lo'), f_hi=hist('f_hi'), c=hist('c'),
        endpoint_scans=hist('endpoint_scans'), modulus_scans=hist('modulus_scans'),
        true_Fg=hist('true_Fg'),
        endpoint_candidates_lo=hist('endpoint_candidates_lo'),
        endpoint_candidates_hi=hist('endpoint_candidates_hi'),
        integer_vectors=hist('integer_vectors'),
        endpoint_gcd_rejections=sum(r['endpoint_gcd_rejections'] for r in rows),
        reconstruction_rejections=sum(r['reconstruction_rejections'] for r in rows),
        coprimality_rejections=sum(r['coprimality_rejections'] for r in rows))


def cpu_name():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r'HARDWARE\DESCRIPTION\System\CentralProcessor\0') as key:
            return winreg.QueryValueEx(key, 'ProcessorNameString')[0].strip()
    except (ImportError,OSError):
        return platform.processor()


def run(args):
    ids = list(range(1,25)) if args.sets == 'all' else [int(s) for s in args.sets.split(',')]
    if not ids or len(set(ids)) != len(ids) or any(i not in range(1,25) for i in ids):
        raise ValueError('--sets must be all or distinct indices in 1..24')
    if args.trials < 1 or args.Cp < 1 or args.Cg < 1:
        raise ValueError('Trials and caps must be positive')
    out = Path(args.out)
    if (out/'metadata.json').exists():
        raise ValueError('Output already contains a run; choose another --out directory')
    out.mkdir(parents=True, exist_ok=True)
    base = Path(__file__).parent
    meta = dict(algorithm='continued-fraction pairwise-coprime recovery', experiment_date='2026-10-12', started_utc=datetime.now(timezone.utc).isoformat(),
        python=sys.version, platform=platform.platform(), cpu=cpu_name(),
        seed=args.seed, Cp=args.Cp, Cg=args.Cg, trials_per_set=args.trials, sets=ids,
        sampler='uniform integer then strictly next prime; reject overflow/duplicates',
        attack_inputs=['public','b','beta','Cp','Cg'],
        timing='single process; complete attack; excludes keygen, evaluation and I/O',
        primality='Key generation only: exact twelve-base test below 318665857834031151167461',
        attack_coprimality='gcd with successive prefix products; no primality test',
        source_hashes={name:hashlib.sha256((base/name).read_bytes()).hexdigest()
                       for name in ['cf_attack.py','key_generation.py','benchmark.py','attack_public.py']})
    (out/'metadata.json').write_text(json.dumps(meta,indent=2),encoding='utf-8')
    summaries, all_rows = [], []
    with (out/'raw_trials.csv').open('w',newline='',encoding='utf-8-sig') as fh:
        writer = None
        for set_id in ids:
            par = PARAMETERS[set_id-1]
            rows = []
            for trial in range(args.trials):
                start = perf_counter()
                public, secret = keygen(par, make_rng(args.seed,set_id,trial))
                keygen_s = perf_counter()-start
                result = attack(public, par.b, par.beta, args.Cp, args.Cg)
                evaluation = evaluate(public,secret,par,result,args.Cp,args.Cg)
                row = dict(set_id=set_id, trial=trial, **asdict(par), G=par.G,
                    Cp=args.Cp,Cg=args.Cg,status=result.status,attack_s=result.elapsed_s,
                    cf_s=result.cf_s, endpoint_s=result.endpoint_s, modulus_s=result.modulus_s,
                    keygen_s=keygen_s,endpoint_scans=result.endpoint_scans,
                    endpoint_pairs=result.endpoint_pairs,integer_vectors=result.integer_vectors,
                    endpoint_candidates_lo=result.endpoint_candidates_lo,
                    endpoint_candidates_hi=result.endpoint_candidates_hi,
                    endpoint_gcd_rejections=result.endpoint_gcd_rejections,
                    reconstruction_rejections=result.reconstruction_rejections,
                    coprimality_rejections=result.coprimality_rejections,
                    modulus_scans=result.modulus_scans,public_validations=result.public_validations,
                    public_sha256=hashlib.sha256(json.dumps(public).encode()).hexdigest(), **evaluation)
                if writer is None:
                    writer = csv.DictWriter(fh, fieldnames=list(row)); writer.writeheader()
                writer.writerow(row); rows.append(row); all_rows.append(row)
                if trial == 0:
                    sample = dict(b=par.b,beta=par.beta,public=[str(x) for x in public])
                    (out/f'public_set_{set_id:02}.json').write_text(json.dumps(sample,indent=2),encoding='utf-8')
            fh.flush()
            summary = dict(set_id=set_id, **asdict(par),G=par.G, **summarize(rows))
            summaries.append(summary)
            (out/'summary.json').write_text(json.dumps(summaries,indent=2),encoding='utf-8')
            print(f"Set {set_id:02}/24: {summary['unique_exact']}/{args.trials} unique exact; "
                  f"mean {summary['mean_s']*1000:.3f} ms; max modulus scans {summary['modulus_scans_max']}",flush=True)
    flatkeys = [k for k,v in summaries[0].items() if not isinstance(v,dict)]
    with (out/'summary.csv').open('w',newline='',encoding='utf-8-sig') as fh:
        w=csv.DictWriter(fh,fieldnames=flatkeys); w.writeheader()
        w.writerows({k:r[k] for k in flatkeys} for r in summaries)
    aggregate = summarize(all_rows)
    (out/'aggregate.json').write_text(json.dumps(aggregate,indent=2),encoding='utf-8')
    meta['completed_utc']=datetime.now(timezone.utc).isoformat()
    (out/'metadata.json').write_text(json.dumps(meta,indent=2),encoding='utf-8')
    print('Finished:',json.dumps({k:aggregate[k] for k in ['trials','unique_exact','truth_in_candidates','mean_s']},indent=2))


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sets',default='all')
    parser.add_argument('--trials',type=int,default=100)
    parser.add_argument('--Cp',type=int,default=2)
    parser.add_argument('--Cg',type=int,default=2)
    parser.add_argument('--seed',type=int,default=20261012)
    parser.add_argument('--out',default='results')
    run(parser.parse_args())
