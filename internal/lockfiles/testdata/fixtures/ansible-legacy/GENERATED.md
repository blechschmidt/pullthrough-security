# ansible-legacy

Hand-written roles-only `requirements.yml` in the old format, a top-level YAML list. Validated
2026-11-12 on the host with ansible-core 2.21.6 (CPython 3.12.3; same scratch venv and scratch `HOME`
as the `ansible` case):

    ansible-galaxy role install -r requirements.yml -p ./roles_out

It exited 0 and all six roles installed. The install directory was deleted afterwards and the file was
not changed after the run. `ansible-galaxy collection install -r requirements.yml` rejects the file:
"Expecting requirements file to be a dict with the key 'collections' that contains a list of
collections to install".

| Entry | Installed as | Version |
| --- | --- | --- |
| `src: geerlingguy.java`, `version: 2.5.0` | `geerlingguy.java` | 2.5.0, from https://github.com/geerlingguy/ansible-role-java/archive/2.5.0.tar.gz |
| `name: geerlingguy.ntp` | `geerlingguy.ntp` | 4.0.1, the newest on Galaxy |
| `src: https://github.com/geerlingguy/ansible-role-firewall`, commit `version`, `name: firewall` | `firewall` | e946e0108fbb49090ed8756fda3737c0abbdb514 (tag 2.6.0) |
| `src: git+https://github.com/geerlingguy/ansible-role-git.git`, `version: "3.0.0"` | `ansible-role-git` | 3.0.0 |
| `src: https://github.com/geerlingguy/ansible-role-apache/archive/refs/tags/4.0.0.tar.gz`, `name: apache` | `apache` | none recorded |
| `geerlingguy.repo-epel,3.1.1` | `geerlingguy.repo-epel` | 3.1.1 |

Notable features:

- `src` is either a Galaxy role name (`owner.role`) or a URL. `name` is optional; it sets the install
  directory name. Without it, ansible-galaxy uses the last URL path segment minus `.git`/`.tar.gz`
  (`ansible-role-git`), or the `src` itself when it is not a URL.
- A `src` containing `github.com` and `http`, but no `+` and not ending in `.tar.gz`, is treated as git
  (ansible-role-firewall has neither `.git` nor `scm:`). `git+https://…` sets the SCM by prefix.
- A `src` ending in `.tar.gz` is downloaded as an archive (GitHub's tag tarball here) and has no version.
- `version` is a tag, a full commit SHA, or a quoted string.
- The last entry is a plain string in the oldest form, `src,version`; ansible-galaxy also accepts
  `src,version,name`.
- Blank lines and full-line comments between entries.
