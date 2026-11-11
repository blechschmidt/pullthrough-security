# Ansible Galaxy

Use the proxy as the only Galaxy server. The examples use the upstream name
`ansible`; replace it with the name your operator gave the upstream
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `ansible` |
| Package source | `https://proxy.example.com/v1/ansible/` |
| Clients | ansible-galaxy (collections) |
| Tested | ansible-galaxy 2.21 (ansible-core): [in CI on every push](../ecosystem-tests-reference.md#ansible) and in the [client lab](../client-lab.md). Roles: not tested (see below). |

## Configure

A `[galaxy_server.*]` entry in `ansible.cfg` (the project's, `~/.ansible.cfg`,
or the file `ANSIBLE_CONFIG` names), and a `server_list` that names it alone:

<!-- verified: ci:ansible lab:ansible -->

```ini
[galaxy]
server_list = pullthrough

[galaxy_server.pullthrough]
url = https://proxy.example.com/v1/ansible/
```

Dependencies of a collection are resolved and downloaded through the proxy as
well.

## Authenticate

Only when the proxy has access control switched on. Add your **proxy token** to
the server's entry:

<!-- verified: lab:ansible -->

```ini
token = <token>
```

ansible-galaxy sends it with the API requests and with the collection download.

## Trust a private CA

ansible-galaxy reads the CA bundle from the environment:

<!-- verified: lab:ansible -->

```sh
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem
```

## Check that it works

<!-- verified: lab:ansible -->

```sh
ansible-galaxy collection install community.general:8.0.0 --collections-path "$PWD/collections"
```

The output names the URL the collection is downloaded from
(`Downloading https://proxy.example.com/v1/ansible/api/v3/…`); with `-vvv`,
every API request.

## Good to know

- **Roles are not covered.** Galaxy only indexes roles; a role's archive is
  hosted on GitHub, and `ansible-galaxy role install` downloads it from there.
- **`requirements.yml`** names collections and versions, not servers; it works
  unchanged.
- **The proxy needs `server.publicUrl`.** ansible-core 2.18 and earlier open a
  collection's download URL exactly as the server sent it, and fail on a
  relative one.
- **Publishing does not go through the proxy** (`ansible-galaxy collection
  publish`).

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  ansible:
    type: ansible
    url: https://galaxy.ansible.com
```

API documents are served live with every link rewritten to the proxy; a
collection tarball is verified against the SHA-256 Galaxy publishes and cached
immutably. Details: [backends: ansible](../backends.md#ansible).
