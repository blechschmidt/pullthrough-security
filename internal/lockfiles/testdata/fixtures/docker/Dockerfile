# syntax=docker/dockerfile:1.7
# escape=\
ARG GO_VERSION=1.22
ARG RUNTIME=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine@sha256:1699c10032ca2582ec89a24a1312d986a3f094aed3d5c1147b19880afe40e052 AS build
WORKDIR /src
COPY --from=docker.io/library/alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc \
     /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
RUN <<EOT
FROM this-line-is-part-of-a-heredoc@sha256:0000000000000000000000000000000000000000000000000000000000000000
EOT
RUN go build -o /out/app ./... \
    # a comment inside a continuation
    && echo built

FROM ${RUNTIME}
COPY --from=build /out/app /app

FROM alpine:3.20 AS unpinned
FROM ${UNDEFINED_IMAGE}
FROM scratch
