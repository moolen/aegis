FROM --platform=$BUILDPLATFORM golang:1.26 AS build

WORKDIR /src

ARG TARGETOS
ARG TARGETARCH

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath -o /out/aegis ./cmd/aegis

FROM gcr.io/distroless/static-debian12

COPY --from=build /out/aegis /usr/local/bin/aegis

ENTRYPOINT ["/usr/local/bin/aegis"]
CMD ["-config", "/etc/aegis/aegis.yaml"]
