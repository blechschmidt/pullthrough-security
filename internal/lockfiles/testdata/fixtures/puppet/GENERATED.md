# puppet

Hand-written: no tool writes a `Puppetfile`. Validated 2026-11-12 with r10k 5.0.3 in podman on
linux/amd64; the file was not changed after the run.

- Image: `docker.io/library/ruby:3.3` =
  `docker.io/library/ruby@sha256:2aa77cb4221aa5ab991b85ff1cd202d6ef74f2d1a578b6f8e7783a391b45dd68`
  (ruby 3.3.13, RubyGems 3.5.22, git 2.47.3).
- The directory holding the Puppetfile was mounted read-only at /work. Commands, in one container
  (version output and the listing of /tmp/x left out):

      gem install r10k -v 5.0.3 --no-document
      cd /work
      r10k puppetfile check
      r10k puppetfile install --moduledir /tmp/x --verbose info

`check` printed "Syntax OK". `install` exited 0 and deployed nine modules:

| Declaration | Deployed |
| --- | --- |
| `mod 'puppetlabs/stdlib', '9.4.1'` | `stdlib` 9.4.1 |
| `mod 'puppetlabs-concat', '9.0.2'` | `concat` 9.0.2 |
| `mod 'puppetlabs/apt', :latest` | `apt` 11.4.1, the newest |
| `mod 'puppetlabs-inifile'` | `inifile` 6.6.0, the newest |
| `archive`, `:tag => 'v9.0.0'` | 585a6bc45241d4356b6e5d1371045a6bd7fde4dd (v9.0.0 is an annotated tag; the tag object is f9a4e2aa51a4e6267c9a9cc981490bcf527f152f) |
| `systemd`, `:commit => '5203ec6f…'` | 5203ec6fce82858ff0ec077d7670a16388a05684 (tag v11.1.0) |
| `motd`, `:branch => 'main'` | d05a8076c54be2d33278da11945a886402e224f0, the tip of `main` on 2026-11-12 (`v8.1.1-2-gd05a807`) |
| `cron`, `ref: 'v5.0.0'` | febc62860af6866590dd5e29fc412a6fd250d8d6 (tag v5.0.0) |
| `puppetlabs-firewall`, `type: 'tarball'` | `firewall`, after r10k checked the SHA-256 |
| `mod 'profile', :local => true` | nothing |

Notable features:

- `forge "https://forge.puppet.com"` in double quotes; every other string is single-quoted.
- Forge module names in both forms, `owner/name` and `owner-name`. The install directory is the part
  after the separator.
- Forge version forms: an exact version string, the symbol `:latest`, and none. r10k's
  `doc/puppetfile.mkd` (tag 5.0.3): with no version "the latest version available at the time will be
  installed, and will be kept at that version"; with `:latest` "the module will be always updated to
  the latest version available".
- Git modules with hash-rocket options `:git`, `:tag`, `:commit`, `:branch`, split over several lines
  with aligned `=>`, one with a trailing `# v11.1.0` comment; and one on a single line in Ruby 1.9 hash
  syntax, `git: '…', ref: '…'`.
- The tarball module uses the keyword form `type:`, `source:`, `version:`. `source` is the Forge file
  URL of puppetlabs-firewall 8.1.0, and `version` is that file's SHA-256 (it equals the Forge API's
  `file_sha256`). r10k verifies it: with a wrong digest the install failed with "Downloaded file does
  not match checksum". r10k unpacks tarball modules as they are (`Minitar.unpack` in
  `lib/r10k/tarball.rb`), so the Forge archive's top-level directory `puppetlabs-firewall-8.1.0/` ends
  up inside `firewall/`.
- `:local => true` marks a module kept in the repository's module directory; r10k deployed nothing
  for it.
- Full-line comments, blank lines, a header comment. LF, trailing newline.
