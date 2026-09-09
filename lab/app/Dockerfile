FROM golang:1.24-alpine AS builder

WORKDIR /src

COPY go.mod ./
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/lab-app \
    ./main.go

FROM alpine:3.22

RUN addgroup -S workshop \
    && adduser -S -G workshop workshop

WORKDIR /app

COPY --from=builder /out/lab-app /app/lab-app

USER workshop

EXPOSE 8081

ENTRYPOINT ["/app/lab-app"]
