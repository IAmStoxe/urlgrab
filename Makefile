export DOCKER_BUILDKIT=1
export GO_VERSION=1.14.5

NULL := /dev/null
BUILD_ARGS := --build-arg GO_VERSION=$(GO_VERSION)\
	--build-arg TAG_NAME=$(GIT_TAG_NAME)

GOOS ?= $(shell go env GOOS)
ifeq ($(COMMIT),)
  COMMIT := $(shell git rev-parse --short HEAD 2> $(NULL))
endif

ifeq ($(TAG_NAME),)
  TAG_NAME := $(shell git describe --always --dirty --abbrev=10 2> $(NULL))
endif

PKG_NAME=github.com/iamstoxe/urlgrab
BINARY:=urlgrab
ifeq ($(GOOS),windows)
	BINARY=urlgrab.exe
endif
STATIC_FLAGS= CGO_ENABLED=0
LDFLAGS := "-s -w \
  -X $(PKG_NAME)/internal.GitCommit=$(COMMIT) \
  -X $(PKG_NAME)/internal.Version=$(TAG_NAME)"

GO_BUILD = $(STATIC_FLAGS) go build -trimpath -ldflags=$(LDFLAGS)

.PHONY: all
all: build

.PHONY: platform-build
platform-build: ## Build dedicated to the local platform
	$(GO_BUILD) -o bin/$(BINARY) .

.PHONY: build
build: ## Build urlgrab in a container
	@mkdir -p bin
	@docker build $(BUILD_ARGS) . \
	--output type=local,dest=./bin \
	--platform local \
	--target urlgrab

.PHONY: build-cross
build-cross: ## Cross compile urlgrab binaries
	GOOS=linux   GOARCH=amd64 $(GO_BUILD) -o ./dist/$(BINARY)-linux-amd64 .
	GOOS=darwin  GOARCH=amd64 $(GO_BUILD) -o ./dist/$(BINARY)-darwin-amd64 .
	GOOS=windows GOARCH=amd64 $(GO_BUILD) -o ./dist/$(BINARY)-windows-amd64.exe .

.PHONY: cross
cross: ## Cross compile urlgrab in a container
	@mkdir -p dist
	@docker build . \
	--output type=local,dest=./dist \
	--target cross

.PHONY: help
help: ## Show help
	@echo Please specify a build target. The choices are:
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
