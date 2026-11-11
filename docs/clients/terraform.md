# Terraform and OpenTofu

Serve the public provider and module registry from the proxy. The examples use
the upstream names `terraform` (registry.terraform.io) and `opentofu`
(registry.opentofu.org); replace them with the names your operator gave the
upstreams ([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `terraform` |
| Package source | `https://proxy.example.com/v1/terraform/v1/providers/` and `…/v1/modules/` |
| Clients | terraform, tofu |
| Tested | Terraform 1.9: [in CI on every push](../ecosystem-tests-reference.md#terraform) (a provider) and in the [client lab](../client-lab.md) (a provider and a module). OpenTofu 1.8: in the client lab. |

## Configure

A `host` block in the CLI configuration overrides service discovery for the
registry's hostname. Provider and module addresses in `.tf` files stay exactly
as they are — `hashicorp/null` and `cloudposse/label/null` resolve through the
proxy.

**Terraform** — `~/.terraformrc` (or the file `TF_CLI_CONFIG_FILE` names):

<!-- verified: lab:terraform -->

```hcl
host "registry.terraform.io" {
  services = {
    "providers.v1" = "https://proxy.example.com/v1/terraform/v1/providers/"
    "modules.v1"   = "https://proxy.example.com/v1/terraform/v1/modules/"
  }
}
```

**OpenTofu** — `~/.tofurc`, for its own registry:

<!-- verified: lab:tofu -->

```hcl
host "registry.opentofu.org" {
  services = {
    "providers.v1" = "https://proxy.example.com/v1/opentofu/v1/providers/"
    "modules.v1"   = "https://proxy.example.com/v1/opentofu/v1/modules/"
  }
}
```

**Modules with a Git source.** A registry only says where a module's source
is, and for most public modules that is a Git repository, which Terraform and
OpenTofu clone with `git`. Send those clones through the proxy's
[Git upstream](git.md) as well:

<!-- verified: lab:terraform lab:tofu -->

```sh
git config --global url."https://proxy.example.com/v1/github/".insteadOf "https://github.com/"
```

## Authenticate

Only when the proxy has access control switched on.

**Providers cannot be installed from a proxy that requires a token.** A
`credentials` block makes the client send the token to the registry API — the
version list and the package descriptor — but it then fetches the checksums,
their signature and the provider package from the URLs in that descriptor
*without* credentials, and the proxy answers `401`:

<!-- output: lab:terraform -->

```
Error: Failed to install provider

Error while installing hashicorp/null v3.2.2: could not query provider
registry for registry.terraform.io/hashicorp/null: failed to retrieve
authentication checksums for provider: 401 Unauthorized returned from
proxy.example.com
```

Where access control is on, the operator has to admit anonymous reads for the
Terraform upstream
([how](../clients.md#clients-that-cannot-present-a-token)).

**Modules can.** The token goes to the registry API with a `credentials` block
for the registry's hostname (the name in the `host` block, not the proxy's):

<!-- verified: lab:terraform -->

```hcl
credentials "registry.terraform.io" {
  token = "<token>"
}
```

and to the Git clone as a header ([Git](git.md#authenticate)):

<!-- verified: lab:terraform lab:tofu -->

```sh
git config --global http."https://proxy.example.com/".extraHeader "Authorization: Bearer <token>"
```

## Trust a private CA

Both clients read the CA bundle from the environment; the Git clone has its own
setting:

<!-- verified: lab:terraform lab:tofu -->

```sh
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem
git config --global http."https://proxy.example.com/".sslCAInfo /etc/ssl/corp-ca.pem
```

## Check that it works

<!-- verified: lab:terraform -->

```sh
terraform init -input=false -no-color
```

`TF_LOG=debug terraform init` prints every URL it requests.

## Good to know

- **`.terraform.lock.hcl` does not change.** It names providers by their
  registry address (`registry.terraform.io/hashicorp/null`) and records
  checksums; the same lock file works with and without the proxy.
- **Signature verification still happens in the client.** The proxy hands out
  the `SHA256SUMS` file and its signature unmodified, having verified both
  itself before caching the provider.
- **A module's Git source is cloned by `git`**, not downloaded from the
  registry: without the `insteadOf` rule the clone goes to the forge directly.
  Modules with an HTTP archive source are fetched through the proxy by the
  registry upstream itself.
- **Terraform checks for new versions of itself** at
  `checkpoint-api.hashicorp.com`, on `terraform version` and `terraform init`
  — the one host besides the proxy the lab saw it look up. Switch it off in
  the CLI configuration (OpenTofu has no such check):

  <!-- verified: lab:terraform -->

  ```hcl
  disable_checkpoint = true
  ```
- **Provider mirrors** (`provider_installation { network_mirror … }`) are a
  different protocol, which the proxy does not serve.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  terraform:
    type: terraform
    url: https://registry.terraform.io
  opentofu:
    type: terraform
    url: https://registry.opentofu.org
```

Version lists and descriptors are served live with their artifact URLs
rewritten to the proxy (which is why `server.publicUrl` must be set); a
provider ZIP is verified against the signed `SHA256SUMS` before it is cached.
Details: [backends: terraform](../backends.md#terraform).
