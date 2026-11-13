# puppet-control-repo

Taken unchanged from a public control repository, downloaded 2026-11-12:

- Repository: https://github.com/example42/psick (Apache-2.0), file `Puppetfile`.
- Commit: 770854c68c2f3f5de6feeedb011760c3a4d894fc (2025-04-16, "Updates and cleanups"), the last
  commit that changed the file. The file is identical on `main` at
  553079a8f9a85992c94cc894cae8e4f09d8813ad (2026-10-22).
- URL: https://raw.githubusercontent.com/example42/psick/770854c68c2f3f5de6feeedb011760c3a4d894fc/Puppetfile
  (git blob fcc191181e07983ec365a54aeba0c4ae5e964954).
- r10k 5.0.3 (same `ruby:3.3` image as the `puppet` case), `r10k puppetfile check`: "Syntax OK", after
  a warning that `:control_branch` cannot be tracked outside a git-backed environment, so the default
  branch would be used. Nothing was installed.

puppetlabs/control-repo was considered first, but at b3e1b4f7ede43d08e9bcf01a3704287c55afff22 its
Puppetfile has only `forge 'https://forge.puppet.com'`; every `mod` line is commented out.

Notable features:

- No `forge` line.
- 34 `mod` declarations: 33 Forge modules, all `:latest` (32 named `owner/name`, one
  `puppetlabs-dropsonde`), and one git module.
- The git module `example42/hieradata` is split over several lines with hash rockets and uses
  `:branch => :control_branch` (a Ruby symbol, not a string) with `:default_branch => 'production'`.
- 33 commented-out `mod` lines, some with versions (`# mod 'puppetlabs-bolt_shim', '0.3.0'`) or git
  sources, three with a second `#` comment after the declaration (e.g.
  `# mod 'puppet/windowsfeature', :latest # :git => 'https://github.com/voxpupuli/puppet-windowsfeature'`),
  and some written `#mod` with no space. The file ends with a commented-out `mod` line.
- LF line endings, trailing newline.
