# Git

Clone and fetch from a forge through the proxy's Git upstream, over HTTPS or
SSH. The examples use the upstream name `github`; replace it with the name your
operator gave the upstream ([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `git` |
| Package source | `https://proxy.example.com/v1/github/<owner>/<repository>.git` |
| Clients | git (and everything that runs it: Go, Terraform, Composer, cargo, pip with VCS requirements) |
| Tested | git 2.49 over HTTPS: [in CI on every push](../ecosystem-tests-reference.md#git) and in the [client lab](../client-lab.md). The SSH endpoint: by the proxy's integration tests, not with these scripts. |

## Configure

### Rewrite the forge's address once

One `insteadOf` rule sends every `https://github.com/` URL through the proxy —
existing clone URLs, submodules, and the Git dependencies of other package
managers — without editing any of them:

<!-- verified: ci:git lab:git -->

```sh
git config --global url."https://proxy.example.com/v1/github/".insteadOf "https://github.com/"
```

<!-- verified: lab:git -->

```sh
git clone https://github.com/octocat/Hello-World.git repo
```

The checkout keeps recording the forge's own URL (`git config --get
remote.origin.url` prints `https://github.com/octocat/Hello-World.git`); the
rewrite happens each time the URL is used, and `git remote -v` shows the
rewritten address.

### Or name the proxy explicitly

<!-- verified: lab:git -->

```sh
git clone https://proxy.example.com/v1/github/octocat/Spoon-Knife.git explicit
```

### SSH

Where the operator runs the proxy's SSH endpoint (it needs mirror mode on the
proxy), the repository path is `<upstream>/<owner>/<repository>.git`:

<!-- untested: the SSH endpoint needs a proxy with git.mirrorDir and server.sshAddr; it is covered by the integration tests of internal/git, not by a lab script -->

```sh
git clone ssh://git@proxy.example.com:2222/github/octocat/Hello-World.git
```

Authentication is by public key only; pin the proxy's host key in
`~/.ssh/known_hosts`.

## Authenticate

Only when the proxy has access control switched on. Give Git your **proxy
token** as a request header, scoped to the proxy's host, and keep URLs free of
it:

<!-- verified: lab:git -->

```sh
git config --global http."https://proxy.example.com/".extraHeader "Authorization: Bearer <token>"
```

**A credential helper, or a token in the URL, does not work.** Git presents a
stored credential only in answer to a `Basic` challenge, and the proxy
challenges with `Bearer`:

<!-- output: lab:git -->

```
remote: missing or invalid credentials
fatal: Authentication failed for 'https://proxy.example.com/v1/github/octocat/Hello-World.git/'
```

## Trust a private CA

Scoped to the proxy's host:

<!-- verified: lab:git -->

```sh
git config --global http."https://proxy.example.com/".sslCAInfo /etc/ssl/corp-ca.pem
```

## Check that it works

<!-- verified: lab:git -->

```sh
git -C repo fetch origin
```

`GIT_CURL_VERBOSE=1 git ls-remote https://github.com/octocat/Hello-World.git`
shows the host each request goes to.

## Good to know

- **Read-only.** The proxy serves fetch and clone (`git-upload-pack`, wire
  protocol v0, v1 and v2); `git push` needs the forge itself. An `insteadOf`
  rule rewrites push URLs too, so a checkout that also pushes needs a second
  rule that keeps its push URL on the forge (`git remote get-url --push origin`
  shows the result):

  <!-- verified: lab:git -->

  ```sh
  git config --global url."https://github.com/".pushInsteadOf "https://github.com/"
  ```
- **Other tools inherit the rule.** Anything that shells out to `git` uses it:
  Terraform modules with Git sources ([Terraform](terraform.md)), Go modules
  fetched from their VCS, Composer `--prefer-source`, pip `git+https://`
  requirements.
- **Git LFS** works without configuration when the operator has enabled it
  (`git.lfs.enabled`): `git lfs pull` negotiates through the proxy and objects
  are cached by their SHA-256.
- **A clone is not gated like a package.** Commits are scanned by the proxy's
  commit scanner for watched repositories, and the verdict gates the *packages*
  built from them; a clone itself is not refused
  ([security model](../security-model.md)).

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  github:
    type: git
    url: https://github.com
```

With `git.mirrorDir` set the proxy keeps bare mirrors and serves from them
(and can serve SSH, `server.sshAddr`); without it, requests are passed through
with ref advertisements cached briefly. Upstream `credentials` let clients
clone private repositories without holding forge tokens. Details:
[backends: git](../backends.md#git).
