
#!/usr/bin/env python3
"""Multi-level wrapper for DQI score functions."""
import argparse, importlib, concurrent.futures as cf, csv, sys
from pathlib import Path
from typing import Tuple, Dict, Callable

ScoreFn = Callable[[str], Tuple[float, dict]]
LEVELS: Dict[int,str] = {1:"dqi_v1",2:"dqi_v2",3:"dqi_v3"}

def _load(level:int)->ScoreFn:
    mod=importlib.import_module(LEVELS[level])
    return getattr(mod,"score")

def _expand(items):
    for itm in items:
        p=Path(itm)
        if p.exists():
            with p.open() as fh:
                for line in fh:
                    line=line.strip()
                    if line and not line.startswith('#'):
                        yield line
        else:
            yield itm

def main():
    ap=argparse.ArgumentParser(description="Multi-level DQI scorer")
    ap.add_argument("domains",nargs="+",help="domain names or files")
    ap.add_argument("-l","--level",type=int,choices=[1,2,3],default=3)
    ap.add_argument("-j","--threads",type=int,default=20)
    ap.add_argument("--csv",type=Path)
    args=ap.parse_args()

    scorer=_load(args.level)
    domains=list(_expand(args.domains))
    rows=[]
    with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for dom,(score_val,detail) in zip(domains, ex.map(scorer,domains)):
            print(f"{dom:<30} L{args.level}-DQI={score_val}")
            rows.append({"domain":dom,"dqi":score_val,**detail})
    if args.csv:
        fieldnames=sorted({k for r in rows for k in r.keys()})
        with args.csv.open('w',newline='') as fh:
            writer=csv.DictWriter(fh,fieldnames=fieldnames)
            writer.writeheader(); writer.writerows(rows)
        print("Saved →",args.csv)

if __name__=='__main__':
    main()
