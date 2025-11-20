# ---------- Build Stage ----------
FROM golang:1.25-alpine AS builder
WORKDIR /app

# 拷贝 go.mod 和 go.sum
COPY go.mod go.sum ./
RUN go mod download

# 拷贝源代码
COPY . .

# 编译
RUN go build -o open-archive

# ---------- Run Stage ----------
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/open-archive .
EXPOSE 8080
CMD ["./open-archive"]
