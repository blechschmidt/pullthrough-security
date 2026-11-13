# carton

Generated 2026-11-12 with Carton v1.0.35 in a throwaway container. cpanfile.snapshot was not
edited afterwards. `local/` (installed modules and the downloaded tarballs) was not kept.

- Tool: Carton v1.0.35, installed with the image's cpanm 1.7049 (`cpanm -n -q Carton`, which
  pulled 26 distributions including Menlo 1.9019 and Menlo-Legacy 1.9022). `carton install`
  installs through Menlo::CLI::Compat 1.9022 with `--quiet --notest`, `--with-all-features`
  and `--with-develop`, from its default mirror `http://cpan.metacpan.org/` (Carton/Mirror.pm).
  perl 5.38.5.
- Image: `docker.io/library/perl:5.38` (Debian 13), digest
  `sha256:587c0c65838dca2fa760e0a0ab169f7260894f208e68f38535ca644f397470c7`.
- Command (cpanfile was hand-written first):

      podman run --rm -v <scratch>:/work -w /work/proj docker.io/library/perl:5.38 bash -c '
        cpanm -n -q Carton && carton install'

  Carton installed 6 distributions into `local/`: Try-Tiny-0.32, Test-Fatal-0.019,
  Role-Tiny-2.002005, Sub-Quote-2.006009, Class-Method-Modifiers-2.15 and Moo-2.005005.

Manifest (cpanfile): `requires 'Try::Tiny', '0.31';` and `requires 'Moo';`, plus the test
phase `on test => sub { requires 'Test::Fatal'; };`. `'0.31'` is a minimum, so 0.32 was installed.

Notable features of cpanfile.snapshot:
- The first line is `# carton snapshot format: version 1.0`, then `DISTRIBUTIONS`. That is the
  only section.
- Each distribution sits at a 2-space indent as `<Dist-Name>-<version>`, sorted by name. Under it,
  at a 4-space indent, come:
  - `pathname: E/ET/ETHER/Try-Tiny-0.32.tar.gz`, relative to a CPAN mirror's `authors/id/`.
    `local/cache/authors/id/<pathname>` existed after the install, and
    `https://cpan.metacpan.org/authors/id/<pathname>` answers 200.
  - `provides:` lists, at 6 spaces, `<Module> <version>`. A module without a version is written
    as `undef` (Moo's `Method::Generate::Accessor`, `Moo::Object` and its `oo` module).
  - `requirements:` lists, at 6 spaces, `<Module> <min version>`, with `0` meaning any version.
    Per `Carton::Snapshot::find_installs` these are the union of the distribution's
    configure, build and runtime `requires` from its installed MYMETA.json. Test-phase
    prereqs and recommends/suggests are not included. The list names modules, not
    distributions, and includes core modules (Carp, Exporter, strict, warnings, B, base,
    constant, Scalar::Util, Test::Builder, ExtUtils::MakeMaker) and `perl 5.006`. None of those
    has a distribution entry.
- Mapping a requirement to a locked distribution needs the provides lists. Moo requires
  `Sub::Defer 2.006006` and `Sub::Quote 2.006006`, and both are provided by Sub-Quote-2.006009.
- **No hash or checksum of any kind.** Carton::Snapshot::Emitter writes only the distribution
  name, `pathname`, `provides` and `requirements`. A digest for a distribution has to come
  from the mirror. The PGP-signed per-author `authors/id/E/ET/ETHER/CHECKSUMS` file lists `md5`,
  `sha256` (plus `-ungz` variants) and `size` for `Try-Tiny-0.32.tar.gz`, and its `sha256`
  ef2d6cab... matches the tarball downloaded from that pathname.
- The project's own requirements are not recorded, and neither are their phases. Test::Fatal,
  which the cpanfile requires only `on test`, is an ordinary entry identical in shape to the
  runtime ones; nothing in the snapshot marks it as test-only. Try::Tiny is both a direct
  runtime requirement and a requirement of Test::Fatal (`Try::Tiny 0.07`).
- No path, user name or credential appears in the file. LF line endings, trailing newline.
