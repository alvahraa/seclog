FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mcp-server ./cmd/mcp-server

FROM alpine:3.20
RUN adduser -D -u 10001 seclog && mkdir -p /data && chown seclog /data
COPY --from=build /out/server /usr/local/bin/server
COPY --from=build /out/mcp-server /usr/local/bin/mcp-server
USER seclog
ENV SECLOG_DB=/data/seclog.db \
    SECLOG_ADDR=:8080
EXPOSE 8080
VOLUME ["/data"]
CMD ["server"]
