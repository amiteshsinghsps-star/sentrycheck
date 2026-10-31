FROM golang:1.25-alpine AS build
WORKDIR /src
COPY integration/go.mod ./go.mod
COPY integration/cmd ./cmd
COPY integration/internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sentrycheck-admission ./cmd/sentrycheck-admission && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sentrycheck-node-probe ./cmd/sentrycheck-node-probe

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /
USER 65532:65532
ENTRYPOINT ["/sentrycheck-admission"]
