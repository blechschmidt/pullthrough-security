# ansible

Hand-written: no tool writes `requirements.yml`. Validated 2026-11-12 with the real tool on the host:
ansible-core 2.21.6 (`ansible-galaxy [core 2.21.6]`, CPython 3.12.3), installed with uv 0.11.14 into a
scratch venv. `HOME` pointed to a scratch directory, so no user config, cache or git config was used.

    ansible-galaxy collection install -r requirements.yml -p ./collections_out
    ansible-galaxy role install -r requirements.yml -p ./roles_out

Both commands exited 0 and every entry installed. The install directories were deleted afterwards and
the file was not changed after the run.

| Entry | Installed |
| --- | --- |
| `community.general`, `version: 8.6.0` | 8.6.0 |
| `ansible.posix`, `version: "==1.5.4"` | 1.5.4 |
| `community.crypto`, `type: galaxy`, `version: ">=2.0.0,<3.0.0"` | 2.26.9, the newest 2.x (the newest overall is 3.5.1) |
| `ansible.utils`, no version, `source: https://galaxy.ansible.com/` | 6.1.1, the newest |
| `https://github.com/ansible-collections/community.mysql.git`, `type: git`, commit `a75d71a7…` | community.mysql 3.10.3, built from the clone |
| Galaxy artifact URL of community.postgresql 3.4.1, `type: url` | community.postgresql 3.4.1 |
| role `geerlingguy.docker`, `version: 7.4.1` | 7.4.1, downloaded from https://github.com/geerlingguy/ansible-role-docker/archive/7.4.1.tar.gz |
| role `src: https://github.com/geerlingguy/ansible-role-nginx.git`, `scm: git`, `version: 3.2.0`, `name: nginx` | `nginx` 3.2.0 |

Notable features:

- Current format: a mapping with a `collections:` list and a `roles:` list, `---` document start,
  full-line comments.
- Collection version forms: bare `8.6.0`; `"==1.5.4"`; a quoted range `">=2.0.0,<3.0.0"`, where the
  comma means AND; and no version at all.
- `type:` is `galaxy` (explicit on community.crypto, the default elsewhere), `git` or `url`.
  `source:` names the Galaxy server for ansible.utils.
- For `type: git`, `name` is the repository URL and `version` is a full commit SHA:
  a75d71a7ff9d6929a08616b90ee4b50d2b15b841, the commit of the annotated tag `3.10.3` (the tag object is
  2cb41b11ae55e77331bfd7257c85ec36d573018e). The collection's `community.mysql` name comes from
  `galaxy.yml` in the repository, not from this file.
- For `type: url`, `name` is the tarball URL
  (`https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/artifacts/community-postgresql-3.4.1.tar.gz`)
  and there is no version; namespace, name and version come from the tarball.
- Roles: a Galaxy role as `name` + `version`; a git role as `src` (an https URL ending in `.git`),
  `scm: git`, `version` (a tag) and `name`, which is the install directory name.
- `collection install -r` installed only the collections. `role install -r` installed only the roles,
  but it also downloaded the `type: url` collection tarball while reading the file.
