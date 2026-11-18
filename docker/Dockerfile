# CargoScope container image, published to ghcr.io/harpelm/cargoscope by
# .github/workflows/docker.yml after each release. Nothing is compiled here:
# the image copies the Linux binary of the GitHub Release
# (docker/dist/<arch>/cargoscope, prepared by the workflow).
#
#   slim (default):   debian:bookworm-slim, enough for scan, update, why, audit-bin
#   full:             rust:1-slim-bookworm, adds cargo for fix and scan --precise
ARG BASE=debian:bookworm-slim
FROM ${BASE}

ARG TARGETARCH
ARG VERSION=dev

LABEL org.opencontainers.image.title="CargoScope" \
      org.opencontainers.image.description="Understand every dependency in your Rust project: advisories, unused dependencies, licenses, versions and why each one is there" \
      org.opencontainers.image.source="https://github.com/HarpeLm/CargoScope" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

COPY dist/${TARGETARCH}/cargoscope /usr/local/bin/cargoscope

# Downloaded advisory and crates.io data; mount a volume here to keep it.
ENV CARGOSCOPE_CACHE_DIR=/cache
WORKDIR /src
ENTRYPOINT ["cargoscope"]
CMD ["--help"]
