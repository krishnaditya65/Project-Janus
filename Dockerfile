# Generic Dockerfile for any cmd/* binary in this module.
# Build with --build-arg SERVICE=<name>, e.g. SERVICE=identity-service or
# SERVICE=iam-server, matching a directory under cmd/.
ARG GO_VERSION=1.26
FROM golang:${GO_VERSION} AS build
ARG SERVICE
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/service ./cmd/${SERVICE}

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/service /service
ENTRYPOINT ["/service"]
