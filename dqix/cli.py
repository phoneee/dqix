
#!/usr/bin/env python3
"""dqix CLI
usage: python -m dqix.cli --level 2 example.com
"""
import argparse, concurrent.futures as cf, importlib
from pathlib import Path
from dqix.core import PROBES, load_weights
from typing import Dict

def load_level(level:int)->Dict:
    weights = load_weights(level)
    return {k:PROBES[k] for k in weights if k in PROBES}

def score_domain(domain:str, probes:Dict):
    total=0.0; details={}
    for pid,probe in probes.items():
        s,d = probe.run(domain)
        details[pid]=d
        total += probe.weight * s
    return round(total*100,1), details

def expand(items):
    for itm in items:
        p=Path(itm)
        if p.exists():
            for line in p.read_text().splitlines():
                line=line.strip()
                if line and not line.startswith('#'): yield line
        else: yield itm

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('targets',nargs='+')
    ap.add_argument('-l','--level',type=int,default=3)
    ap.add_argument('-j','--threads',type=int,default=20)
    args=ap.parse_args()

    probes = load_level(args.level)
    domains=list(expand(args.targets))
    with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for dom,(score,det) in zip(domains, ex.map(lambda d: score_domain(d,probes), domains)):
            print(f"{dom:<30} DQI-L{args.level}={score}")

if __name__=='__main__':
    main()
