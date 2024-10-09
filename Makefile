
DOCKER_IMAGE ?= claude-cni
IMAGE_TAG_VERSION=$(shell git describe --tags --always)

VERSION=$(shell git rev-parse  HEAD)
BUILDTIME=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')


.PHONY: docker-build
docker-build:
	docker build -f Dockerfile  -t $(DOCKER_IMAGE):$(IMAGE_TAG_VERSION) .

.PHONY: docker-push
docker-push:
	docker tag ${DOCKER_IMAGE}:${IMAGE_TAG_VERSION} ${DOCKER_IMAGE}:latest
	docker push ${DOCKER_IMAGE}:${IMAGE_TAG_VERSION}
	docker push ${DOCKER_IMAGE}:latest

.PHONY: build
# build
build:
	rm -rf bin/
	mkdir -p bin/ && CGO_ENABLED=0 GOOS=linux GOARCH=amd64  go build -ldflags "-extldflags=-static -X main.version=$(IMAGE_TAG_VERSION) -X main.buildtime=$(BUILDTIME) " -o ./bin/ ./...

