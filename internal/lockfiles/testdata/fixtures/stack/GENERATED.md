# stack

Generated 2026-11-12 by real Stack in a throwaway container. stack.yaml.lock is unedited tool
output (Stack wrote it with mode 0600; the copy here is 0644). stack.yaml and bar.cabal were written
by hand first, and Stack did not change them (sha256 compared before and after). Nothing was built.

- Tool: Stack 3.3.1 (Git revision 7540878295db1899b55855cc765ab1eacdf30f3c, x86_64, hpack-0.37.0), system GHC 9.8.4.
- Image: `docker.io/library/haskell:9.8` = `haskell@sha256:ed21f5c111bcdaff2350b5d9efe66345868e8e0dfd9bd5e570ba43a2f6b755ff`
- Inputs: `stack.yaml` (`snapshot: lts-23.28`, whose compiler is ghc-9.8.4, the image's GHC;
  `packages: [.]`; three extra-deps: `acme-missiles-0.3` from Hackage, which is not in the
  snapshot, plus two git extra-deps by commit) and `bar.cabal` (a library depending on base,
  text, acme-missiles, splitmix and say). A one-line src/Bar.hs existed but is not part of the fixture.

Command (fresh scratch `STACK_ROOT`, so Stack downloaded the snapshot and the Hackage index
itself; `build --dry-run` only plans):

    podman run --rm -v <scratch>:/work -v <scratch>/stack-root:/stackroot -w /work/proj -e STACK_ROOT=/stackroot \
      docker.io/library/haskell:9.8 stack --system-ghc --no-install-ghc build --dry-run

The STACK_ROOT had been filled by a first attempt with only the say git dependency (same command,
another project directory). That attempt's lock file had no git entry at all; see the last bullet.

Notable features of stack.yaml.lock:

- YAML: a four-line `#` header, then `packages:` (a list of `{completed, original}` pairs) and
  `snapshots:`. Keys inside each mapping are in alphabetical order.
- Hackage entry: `original: {hackage: acme-missiles-0.3}` and `completed:` with
  `hackage: acme-missiles-0.3@sha256:2ba66a092a32593880a87fb00f3213762d7bca65a687d45965778deb8694c5d1,613`
  (one unquoted scalar) and `pantry-tree: {sha256, size}`.
  The `@sha256:<hex>,<size>` part is the SHA-256 and byte length of the package's `.cabal` file
  revision, not of the tarball. Checked: https://hackage.haskell.org/package/acme-missiles-0.3/revision/0.cabal
  (its only revision) is 613 bytes with exactly this sha256, also listed by Hackage's revisions
  API. The tarball's own sha256 (`e563d8b5…`) appears nowhere in the lock.
- `pantry-tree` is pantry's content key for the unpacked package: SHA-256 and byte length of
  pantry's serialisation of the file tree (`renderTree` in pantry's int/Pantry/Types.hs:
  `map:` followed, per file in path order, by `<len>:<path>`, the file's raw 32-byte SHA-256,
  `<size>:` and `N`, or `X` for executables). Recomputed from scratch for both entries and equal:
  acme-missiles `614bc0cc…`/226 from the Hackage tarball's 4 files (top directory stripped, the
  `.cabal` file taken from the index revision); splitmix `ba415e7b…`/2939 from
  `git -c core.autocrlf=false archive` of the commit, 46 files, the whole repository
  (including the nested `splitmix-tests/` package), with the symlink `tools/LICENSE` stored with
  its target's content.
- Git entry: `original: {commit, git}` exactly as in stack.yaml;
  `completed: {commit: 419c763825d6e0dceb266ef64e9cbcb7e07a481f, git: https://github.com/haskellari/splitmix.git, name: splitmix, pantry-tree: {…}, version: 0.1.3.2}`.
  The commit is the one tag v0.1.3.2 points to (`git cat-file -t`: commit). The snapshot has
  splitmix 0.1.3.1; the git extra-dep replaces it.
- Snapshot entry: `original: lts-23.28`, `completed: {sha256: 7e724f34…, size: 684460, url: https://raw.githubusercontent.com/commercialhaskell/stackage-snapshots/master/lts/23/28.yaml}`.
  sha256 and size are those of the snapshot YAML at that URL (downloaded and checked).
- The lock lists only extra-deps and the snapshot. Neither text (from the snapshot/GHC) nor the
  local package bar is in it.
- The git extra-dep say (https://github.com/fpco/say.git at e667d40e…) has NO lock entry, although
  stack.yaml names it and Stack plans to build it. Its repository has only an hpack `package.yaml`,
  no `.cabal` file. Stack prints a DEPRECATED warning and leaves such a location out of the lock
  file (Stack 3.3.1 src/Stack/Config.hs: `if cplHasCabalFile cpl … else warnMissingCabalFile`).
  A reader of stack.yaml.lock alone does not see it.
- LF line endings, trailing newline.
