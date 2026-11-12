# docker

Hand-written. The digests are real: Docker Hub's and gcr.io's manifest-list digests for the named
tags, fetched from the registries' APIs on 2026-11-12.

- Dockerfile: global ARGs expanded in FROM; `COPY --from=<image>` pins an image too; a heredoc body
  that looks like a FROM line; a comment inside a continuation; an unpinned FROM, a FROM from an
  undefined build argument, `scratch` and an earlier stage.
- compose.yaml: an image inherited through a YAML merge key, a quoted image, a service built from a
  Dockerfile, an image from an environment variable's default, an image pulled through the proxy's
  registry alias (proxy.example.com/dockerhub/…).
- legacy/docker-compose.yml: the version 1 format, services at the top level.
