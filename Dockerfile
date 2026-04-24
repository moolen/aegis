FROM golang:1.26 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /out/aegis ./cmd/aegis

FROM gcr.io/distroless/static-debian12

COPY --from=build /out/aegis /usr/local/bin/aegis

ENTRYPOINT ["/usr/local/bin/aegis"]
CMD ["-config", "/etc/aegis/aegis.yaml"]
