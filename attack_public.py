"""Run only the public-key attack, without key generation or a saved secret."""
import argparse
import json
from pathlib import Path
from cf_attack import attack

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('public_json')
parser.add_argument('--Cp',type=int,default=2)
parser.add_argument('--Cg',type=int,default=2)
parser.add_argument('--out',default='recovered.json')
args=parser.parse_args()
source=json.loads(Path(args.public_json).read_text(encoding='utf-8'))
result=attack([int(x) for x in source['public']],source['b'],source['beta'],args.Cp,args.Cg)
out=dict(status=result.status,Cp=args.Cp,Cg=args.Cg,elapsed_s=result.elapsed_s,
    endpoint_scans=result.endpoint_scans,endpoint_pairs=result.endpoint_pairs,
    modulus_scans=result.modulus_scans,
    candidates=[dict(p=[str(p) for p in k.p],g=str(k.g),u=str(k.u)) for k in result.candidates])
target=Path(args.out)
if target.exists():
    raise ValueError('Output exists; choose a different --out filename')
target.write_text(json.dumps(out,indent=2),encoding='utf-8')
print(f'{result.status}: {len(result.candidates)} candidate(s); {result.elapsed_s*1000:.3f} ms; saved to {target}')
