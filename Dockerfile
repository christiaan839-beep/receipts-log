# Build a static binary, then copy it into a distroless image that runs as
# the unprivileged "nonroot" user (uid 65532). Base images are pinned by
# digest; update the digests deliberately.
# The build stage runs on the build machine's platform and cross-compiles
# for the target, so a multi-platform build needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/receipts-log ./cmd/receipts-log \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/receipts-log /usr/local/bin/receipts-log
# The data directory belongs to the runtime user so a fresh volume is writable.
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV RECEIPTS_LOG_DATA=/data \
    RECEIPTS_LOG_ADDR=:8080
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/receipts-log"]
CMD ["serve"]
