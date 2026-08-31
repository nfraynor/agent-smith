# syntax=docker/dockerfile:1.7
FROM golang:1.25-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/remoteops ./cmd/remoteops

FROM build AS test
RUN go test ./...
RUN go vet ./...

# The Docker CLI image supplies the Compose plugin. util-linux supplies nsenter,
# which is inert unless the separate God Mode deployment is selected.
FROM docker:29-cli AS runtime
RUN apk add --no-cache ca-certificates util-linux
COPY --from=build /out/remoteops /usr/local/bin/remoteops
RUN mkdir -p /config /data && chmod 0700 /data
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/remoteops"]
