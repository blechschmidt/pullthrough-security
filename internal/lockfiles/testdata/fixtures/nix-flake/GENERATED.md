# nix-flake

Generated 2026-11-12 by real Nix in a throwaway container. flake.lock is unedited tool output.
flake.nix was written by hand first and Nix did not change it.

- Tool: Nix 2.35.6 (`nix --version`), as shipped in `docker.io/nixos/nix:latest`.
- Image: run by digest, with podman 4.9.3.
  - Manifest-list digest: `docker.io/nixos/nix@sha256:b49cb33f3a7e5cf3933ad8774529de0e3807ec5cf54987aa7ccdfb49f2fc55ed`.
  - linux/amd64 manifest: `sha256:a3b3e3eb3883e5af5327757c5304c0093426a0d11c58a9056df46cfefe30319e`.
  - Image ID: `sha256:8b07b6e940ba744a261395bd19bd399c58136d7a342fca8e359e68ffff688a67`.
  - Label `org.opencontainers.image.version`: 2.35.6.
- Command: the flake directory is a plain directory, not a git repo, so Nix treated it as a
  `path:` flake. The container used the image's default nix.conf:

      podman run --rm -v <scratch>/nix-flake:/work docker.io/nixos/nix@sha256:b49cb33f… sh -c '
        cd /work
        nix --extra-experimental-features nix-command --extra-experimental-features flakes flake lock'

  Nix reported `warning: creating lock file "/work/flake.lock"` and listed the added inputs.
  A second `flake lock` in the same container left the file byte-identical.
- Locking needs the GitHub REST API to resolve each `github:` ref, via
  `https://api.github.com/repos/<owner>/<repo>/commits/<ref>`.
  - This run used 3 unauthenticated requests, one each for nixpkgs, flake-utils (`HEAD`) and
    home-manager. The quota counter went from 60 to 57.
  - Earlier attempts failed with HTTP 403 "API rate limit exceeded" because the host's shared
    quota of 60 per hour was used up; they wrote nothing.
  - Tarballs were downloaded without API calls.

Inputs in flake.nix:
- `nixpkgs`: `github:NixOS/nixpkgs/nixos-24.11`.
- `flake-utils`: `github:numtide/flake-utils`. It has its own input `systems`, which gives a
  transitive node.
- `home-manager`: `github:nix-community/home-manager/release-24.11`, with
  `inputs.nixpkgs.follows = "nixpkgs"`.
- `flake-compat`: `git+https://github.com/edolstra/flake-compat?ref=refs/tags/v1.1.0` with
  `flake = false`.
- `flake-utils-v1`: the GitHub archive URL
  `https://github.com/numtide/flake-utils/archive/refs/tags/v1.0.0.tar.gz`, as a flake.
  flake-utils v1.0.0 has no inputs.

Notable features of flake.lock (3120 bytes, 114 lines, 2-space JSON, LF, trailing newline, no
paths):

- Top level: `"nodes": {...}, "root": "root", "version": 7`. All object keys are sorted,
  including the node names: flake-compat, flake-utils, flake-utils-v1, home-manager, nixpkgs,
  root, systems.
- `root` names the root node. The root node has only `inputs` (input name → node name). It has
  no `locked`/`original`, so the lock says nothing about the flake's own source.
- Other nodes have `locked` and `original`, plus `inputs` when the input has inputs of its
  own, plus `"flake": false` for non-flake inputs (flake-compat). Node names are input names
  ("flake-utils-v1", "systems"), not package names.
- `inputs` values come in two forms:
  - a string naming a node: flake-utils → `"systems": "systems"`;
  - an array, which is a `follows` path from the root: home-manager →
    `"nixpkgs": ["nixpkgs"]`.

  home-manager's own nixpkgs input therefore has no node of its own. It is the root's
  `nixpkgs`.
- `locked` fields by type:
  - `github` (nixpkgs, flake-utils, systems, home-manager): `lastModified`, `narHash`, `owner`,
    `repo`, `rev`, `type`. `locked` has no `ref`. The branch is only in `original.ref`
    (`nixos-24.11`, `release-24.11`). flake-utils has no ref, so Nix resolved the repository's
    default branch (`HEAD`). systems has no ref either.
  - `git` (flake-compat): `lastModified`, `narHash`, `ref` (`refs/tags/v1.1.0`), `rev`,
    `revCount`, `type`, `url` (`https://github.com/edolstra/flake-compat`, as written,
    without `.git`). `original` is `{ref, type, url}`.
  - `tarball` (flake-utils-v1): `lastModified`, `narHash`, `type`, `url`. There is no `rev`, and
    `locked.url` equals `original.url`.
- `narHash` is the SRI SHA-256 of the NAR serialisation of the fetched source tree. It is not a
  hash of the downloaded file: the v1.0.0 tarball file has sha256 b542313d…d7b7, while the
  node's narHash is `sha256-gzTw/v1v…`. All 6 values were checked three ways:
  - In a second container, `nix flake archive` fetched every locked input. For each store path,
    `nix hash path` and the SHA-256 of `nix-store --dump` both equal the lock's narHash.
  - Independently of Nix, a small NAR serialiser on the host hashed:
    - for every `github` node, the GitHub archive `https://github.com/<owner>/<repo>/archive/<rev>.tar.gz`,
      unpacked with its top-level directory stripped;
    - for the `tarball` node, the tag archive, also unpacked with its top-level directory
      stripped;
    - for the `git` node, `git archive <rev>` of a fresh clone.

    All of these match.
- `rev` is the full 40-hex commit id. For the git input it is the commit that the lightweight
  tag v1.1.0 points to, ff81ac966bb2cae68946d5ed5fc4994f96d0ffec. `revCount` is 69, equal to
  `git rev-list --count v1.1.0`.
- The resolved revs are the branch heads seen with `git ls-remote` / `git fetch` at generation
  time: nixpkgs 50ab793786d9…, home-manager d5f1f641b289…, flake-utils cd489559845d….
- `lastModified` is Unix seconds.
  - For the four github nodes and the git node it is the commit's timestamp: all five checked
    against the fetched commit objects; author and committer time are equal for these commits.
  - For the tarball it is 1652776076 (2022-05-17 08:27:56 UTC), the mtime of every entry in
    the tarball. GitHub sets that to the time of commit 04c1b180862888302ddfb2e3ad9eaa63afc60cf8,
    which the tarball's pax comment names.
- The transitive `systems` node (nix-systems/default d36eeed1…) was not fetched while locking.
  Nix copied it from flake-utils' own flake.lock at rev cd489559…, which has a byte-for-byte
  equal JSON entry. Only the later `nix flake archive` downloaded it.
