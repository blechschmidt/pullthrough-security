# cabal-freeze

Generated 2026-11-12 by real cabal-install in a throwaway container. cabal.project.freeze is
unedited tool output. foo.cabal and cabal.project were written by hand first, and cabal did not
change them (sha256 compared before and after). Nothing was built.

- Tool: cabal-install 3.14.1.1 (Cabal library 3.14.1.1), GHC 9.8.4.
- Image: `docker.io/library/haskell:9.8` = `haskell@sha256:ed21f5c111bcdaff2350b5d9efe66345868e8e0dfd9bd5e570ba43a2f6b755ff`
- Inputs: `foo.cabal` (library, `build-depends: base, aeson, text`, no version bounds) and
  `cabal.project` (`packages: .`). A one-line src/Foo.hs existed but is not part of the fixture.

Command (fresh `CABAL_DIR`, so cabal wrote a default config and downloaded the Hackage index):

    podman run --rm -v <scratch>:/work -v <scratch>/cabal-dir:/cabal -w /work/proj -e CABAL_DIR=/cabal \
      docker.io/library/haskell:9.8 sh -c 'cabal update && cabal freeze'
    # cabal update: "The index-state is set to 2026-11-12T22:43:29Z."

Notable features of cabal.project.freeze:

- cabal.project syntax, three fields: `active-repositories: hackage.haskell.org:merge`, one long
  `constraints:` field with comma-separated entries on continuation lines (13-space indent), and
  `index-state: hackage.haskell.org 2026-11-12T22:43:29Z` last.
- Version entries read `any.<package> ==<version>` (72 of them, e.g. `any.aeson ==2.3.2.0`,
  `any.text ==2.1.1`). `any.` is a qualifier: in cabal's constraint syntax it makes the
  constraint apply to every instance of the package in the plan, including setup and build-tool
  dependencies.
- Flag entries read `<package> +flag -flag …` (27 of them, e.g. `aeson +ordered-keymap`,
  `hashable -arch-native -random-initial-seed`): every flag of the package with the value the
  solver chose. They pin no version.
- No hashes, no URLs, no cabal-file revisions. Which `.cabal` revision a version means follows
  from `index-state` (the Hackage index as of that time).
- No `installed` constraints. The 23 packages that come with GHC and were taken from its global
  package DB (array, base, binary, bytestring, containers, deepseq, directory, exceptions, filepath,
  ghc-bignum, ghc-boot-th, ghc-prim, mtl, parsec, pretty, process, rts, stm, template-haskell,
  text, time, transformers, unix: `pre-existing` in dist-newstyle/cache/plan.json, and in
  `ghc-pkg list --global`) look exactly like Hackage packages, e.g. `any.base ==4.19.2.0`,
  `any.rts ==1.0.2`. Only the other 49 would be downloaded from Hackage.
- The local package foo is not listed.
- It is the whole install plan, not only what the code needs: QuickCheck 2.19.0.0 is there
  because aeson 2.3.2.0's library depends on it; tasty 1.5.5 (and through it
  optparse-applicative, ansi-terminal, prettyprinter, …) because vector 0.13.2.0's internal
  library `benchmarks-O2` depends on it; hsc2hs 0.68.10 is a build tool (an executable) of
  terminal-size. All three reasons are read from plan.json.
- LF line endings, trailing newline.
