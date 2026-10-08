"""Explicit offline development CRS generation for an existing DGFlow runtime.

This is single-party trusted setup, not a ceremony. It writes PUBLIC proving and
verification keys plus a pinned circuit manifest; setup trapdoor is not exported.
Roles/experiment start never invoke this script or generate parameters implicitly.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,required=True)
    parser.add_argument('--dimension',type=int,default=650)
    parser.add_argument('--bits',type=int,default=8)
    parser.add_argument('--workers',type=int,default=4)
    parser.add_argument('--native-dir',type=Path)
    args=parser.parse_args()
    if args.native_dir: sys.path.insert(0,str(args.native_dir.resolve()))
    sys.path.insert(0,str(ROOT/'src'))
    from dgfl.crypto.lego_registry import Registry
    result=Registry(args.runtime).create_development(args.dimension,args.bits,workers=args.workers)
    print(json.dumps(result,indent=2),flush=True)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
