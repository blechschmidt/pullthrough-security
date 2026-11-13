# helm-v1

Generated 2026-11-12 with Helm v3.16.3 (GitCommit cfd07493f46efc9debd9cc1b02a0961186df7fdf,
go1.22.7) on the host, in a scratch copy of this directory, with an empty HOME:

    env -i HOME=<scratch>/home PATH=/usr/bin:/bin helm dependency update

`Chart.yaml` (Helm 2 style, `apiVersion: v1`) and `requirements.yaml` were written by hand.
`requirements.lock` is the tool's output, unedited. The downloaded `charts/*.tgz` is not kept.

- Helm 3 wrote `requirements.lock`, not `Chart.lock`. It does so because the chart's apiVersion is
  `v1` (`writeLock(..., c.Metadata.APIVersion == "v1")` in `pkg/downloader/manager.go`). It printed
  no deprecation warning.
- The format is the same as Chart.lock: `dependencies` (each with only `name`, `repository`,
  `version`), `digest` and `generated`.
- `requirements.yaml` has a single dependency, prometheus-pushgateway `3.11.2` from
  https://prometheus-community.github.io/helm-charts. That chart is itself `apiVersion: v2`
  according to the index, and Helm did not object.
- `digest` is computed as in the helm fixture: `"sha256:" + hex(sha256(json.Marshal([requirements.yaml
  dependencies, locked dependencies])))`. Recomputed from the two files: it matches
  `sha256:99b29df7…06fa`.
- There is no per-chart digest. The index's `digest:` for `prometheus-pushgateway-3.11.2.tgz` is
  `91d48ea7…`, which equals the sha256 of the downloaded archive, and it is not in the lock.
- YAML, LF, trailing newline.
