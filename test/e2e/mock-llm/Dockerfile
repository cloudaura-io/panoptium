# Build the mock LLM server binary
FROM golang:1.22 AS builder

WORKDIR /workspace
COPY go.mod go.mod
COPY main.go main.go

RUN CGO_ENABLED=0 GOOS=linux go build -a -o mock-llm .

# Use distroless as minimal base image
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/mock-llm .
USER 65532:65532
EXPOSE 8080

ENTRYPOINT ["/mock-llm"]
