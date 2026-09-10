FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/scanner-backend \
    .

FROM alpine:3.22

RUN addgroup -S scanner \
    && adduser -S -G scanner scanner

WORKDIR /app

COPY --from=builder /out/scanner-backend /app/scanner-backend

USER scanner

EXPOSE 8080

ENTRYPOINT ["/app/scanner-backend"]