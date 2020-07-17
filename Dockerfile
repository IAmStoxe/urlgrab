# syntax = docker/dockerfile:experimental
ARG GO_VERSION=1.14.5
ARG GOLANGCI_LINT_VERSION=v1.27.0-alpine

### Base stage
FROM --platform=${BUILDPLATFORM} golang:${GO_VERSION} AS base
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.* .
RUN --mount=type=cache,target=/root/.cache/go-build \
    go mod download
COPY . .

### Build stage
FROM base AS build
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/root/.cache/go-build \
  GOOS=${TARGETOS} \
  GOARCH=${TARGETARCH} \
  make platform-build

### urlgrab binary
FROM scratch AS urlgrab
COPY --from=build /src/bin .


### cross build stage
FROM base AS build-cross
ARG TAG_NAME
ENV TAG_NAME=$TAG_NAME
RUN --mount=type=cache,target=/root/.cache/go-build \
    make build-cross

FROM scratch AS cross
COPY --from=build-cross /src/dist .
