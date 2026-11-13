// Evaluates versions and ranges with two releases of node-semver (npm's
// bundled copy, and the newest): a range the two read differently is marked
// "differs". Usage: node npm.js versions.lines ranges.lines outdir
// (SEMVER_A, SEMVER_B: the two package directories).
const fs = require('fs')
const A = require(process.env.SEMVER_A)
const B = require(process.env.SEMVER_B)
const [vfile, rfile, outdir] = process.argv.slice(2)
const lines = f => [...new Set(fs.readFileSync(f, 'utf8').split('\n').filter(l => l !== '').map(l => JSON.parse(l)))]
const vers = lines(vfile)
const ranges = lines(rfile)
const clean = v => { try { return A.clean(v) } catch (e) { return null } }
for (const v of vers) {
  let b = null
  try { b = B.clean(v) } catch (e) {}
  if (clean(v) !== b) throw new Error('the releases clean ' + JSON.stringify(v) + ' differently')
}
const sorted = vers.map(clean).filter(v => v !== null).sort(A.compare)
const rank = new Map()
let r = -1
let prev = null
for (const v of sorted) { if (prev === null || A.compare(prev, v) !== 0) r++; if (!rank.has(v)) rank.set(v, r); prev = v }
fs.writeFileSync(outdir + '/npm-versions.tsv', vers.map(v => JSON.stringify(v) + '\t' + (clean(v) === null ? '-1' : String(rank.get(clean(v))))).join('\n') + '\n')
const universe = vers.filter(v => { try { return A.valid(v) !== null } catch (e) { return false } }).slice(0, 220)
const evalWith = (S, rg) => {
  let R
  try { R = new S.Range(rg) } catch (e) { return 'invalid\t\t' }
  return 'ok\t' + JSON.stringify(R.range) + '\t' + universe.map(v => S.satisfies(v, rg) ? '1' : '0').join('')
}
let out = '# ' + JSON.stringify(universe) + '\n'
for (const rg of ranges) {
  const a = evalWith(A, rg)
  out += JSON.stringify(rg) + '\t' + (a === evalWith(B, rg) ? a : 'differs\t\t') + '\n'
}
fs.writeFileSync(outdir + '/npm-ranges.tsv', out)
