# Build a static binary, then copy it into a distroless image that runs as
# the unprivileged "nonroot" user (uid 65532). Base images are pinned by
# digest; update the digests deliberately.
FROM golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
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
