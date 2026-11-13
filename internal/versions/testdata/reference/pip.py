# Evaluates versions and specifier sets with the packaging library.
# Usage: python3 -I pip.py versions.lines constraints.lines outdir
import json, sys
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier

def lines(path):
    return list(dict.fromkeys(json.loads(l) for l in open(path, encoding='utf-8').read().split('\n') if l))

vfile, cfile, outdir = sys.argv[1:4]
vers, cons = lines(vfile), lines(cfile)

def parse(v):
    try:
        return Version(v)
    except InvalidVersion:
        return None

parsed = {v: parse(v) for v in vers}
ranks, rank, prev = {}, -1, None
for p in sorted({p for p in parsed.values() if p is not None}):
    if prev is None or p != prev:
        rank += 1
    ranks[p], prev = rank, p
with open(outdir + '/pip-versions.tsv', 'w', encoding='utf-8') as f:
    for v in vers:
        f.write(json.dumps(v) + '\t' + (str(ranks[parsed[v]]) if parsed[v] is not None else '-1') + '\n')
universe = [v for v in vers if parsed[v] is not None][:240]
with open(outdir + '/pip-constraints.tsv', 'w', encoding='utf-8') as f:
    f.write('# ' + json.dumps(universe) + '\n')
    for c in cons:
        try:
            ss = SpecifierSet(c)
        except InvalidSpecifier:
            f.write(json.dumps(c) + '\tinvalid\t\t\n')
            continue
        try:
            bits = ''.join('1' if ss.contains(v) else '0' for v in universe)
        except InvalidVersion:
            # packaging parses the set but cannot evaluate it.
            f.write(json.dumps(c) + '\traises\t\t\n')
            continue
        f.write(json.dumps(c) + '\tok\t\t' + bits + '\n')
