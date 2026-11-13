# helm

Generated 2026-11-12 with Helm v3.16.3 (GitCommit cfd07493f46efc9debd9cc1b02a0961186df7fdf,
go1.22.7) on the host, in a scratch copy of this directory, with an empty HOME:

    env -i HOME=<scratch>/home PATH=/usr/bin:/bin helm dependency update

No `helm repo add` was needed. For a repository URL that is not configured, Helm fetches the
`index.yaml` itself: it printed "Getting updates for unmanaged Helm repositories...". Docker Hub
was used anonymously.

`Chart.yaml` and `subcharts/fixture-lib/Chart.yaml` were written by hand. `Chart.lock` is the
tool's output, unedited. The `charts/*.tgz` archives that `helm dependency update` downloaded are
not kept.

- `Chart.yaml` is `apiVersion: v2` with 4 dependencies:
  - kube-state-metrics `8.7.1` from https://prometheus-community.github.io/helm-charts.
  - redis `28.3.12` from `oci://registry-1.docker.io/bitnamicharts`.
  - prometheus-node-exporter `"~4.56"` from the same HTTPS repository, with
    `alias: node-exporter` and `condition: node-exporter.enabled`.
  - fixture-lib `0.1.0` from `file://subcharts/fixture-lib`, a local library chart.
- `Chart.lock` has the keys `dependencies`, `digest` and `generated`. Each dependency has only
  `name`, `repository` and `version`, and the keys appear in that alphabetical order.
- Versions are exact:
  - `~4.56` (>= 4.56.0, < 4.57.0) became `4.56.3`, the newest 4.56.x in the index.
  - The local chart's `0.1.0` was read from its own Chart.yaml.
  - `repository` is copied as written, including the `oci://` and `file://` URLs.
- `alias` and `condition` are not in the lock. The entry is still named
  `prometheus-node-exporter`, not `node-exporter`.
- `digest` is `"sha256:" + hex(sha256(J))`, where `J` is Go's `json.Marshal` of the two-element
  array `[Chart.yaml dependencies, Chart.lock dependencies]`.
  - Source: `resolver.HashReq` in helm v3.16.3 `internal/resolver/resolver.go`, called from
    `Manager.Update` in `pkg/downloader/manager.go`.
  - Each element is a `chart.Dependency` with the fields name, version, repository, condition,
    tags, enabled, import-values and alias, in that order. Empty fields are left out, and the JSON
    is compact.
  - The first array holds the request, including `"version":"~4.56"`, `"condition"` and `"alias"`.
    The second holds name/version/repository of the resolved entries.
  - Recomputed from the two files: it matches `sha256:4aafa58d…5771`. The digest covers the
    requested and resolved dependency lists, not chart contents.
- Chart.lock has no per-chart digest. These digests exist elsewhere, and none of them is in
  Chart.lock:
  - The repository `index.yaml` has a `digest:` for every chart version, which is the sha256 of the
    `.tgz`. `kube-state-metrics-8.7.1.tgz` is `368acd18…` and
    `prometheus-node-exporter-4.56.3.tgz` is `b3051e01…`; both equal the sha256 of the downloaded
    archives.
  - redis came from OCI. Helm printed the manifest digest
    `sha256:a80baff98e6d4865d13d303855e2495e3049c2df515ac729c5f2530e265ef796`. The manifest's one
    layer (`application/vnd.cncf.helm.chart.content.v1.tar+gzip`) is `sha256:26dfb7fd…`, which is
    the sha256 of `redis-28.3.12.tgz`.
- `generated` is the UTC run time as RFC 3339 with fractional seconds
  (`"2026-11-12T22:59:54.62141309Z"`, quoted).
- YAML with list items at column 0 (`- name: …`), LF, trailing newline.
