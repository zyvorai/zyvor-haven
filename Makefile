# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
.PHONY: crds operators dev prod doctor wait secrets-prod ui-install ui-dev ui-build console-build console-test console-run controller-build controller-deploy docs-install docs-serve docs-build image-console image-controller image-idp images idp-build idp-dev build-haven build-darwin macos-pkg

IMAGE_REGISTRY ?= ghcr.io/zyvorai
VERSION ?= 0.1.0
DOCKER ?= docker

crds:
	kubectl apply -f config/crd/haven.identity_identityplanes.yaml

operators:
	bash deploy/operators/install.sh

dev: crds
	kubectl apply -k deploy/overlays/dev

prod: crds
	@echo "Prod overlay needs secrets + TLS. See deploy/overlays/prod/README.md"
	kubectl apply -k deploy/overlays/prod

wait:
	bash hack/wait-plane.sh

doctor:
	bash cli/haven doctor platform -n identity

admin:
	bash cli/haven admin platform -n identity

secrets-prod:
	bash hack/gen-prod-secrets.sh

samples-dev:
	kubectl apply -f config/samples/identityplane-dev.yaml

samples-prod:
	kubectl apply -f config/samples/identityplane-prod.yaml

ui-install:
	cd ui/web && npm install

ui-dev:
	cd ui/web && npm run dev

ui-build:
	cd ui/web && npm run build
	cp -r ui/web/dist cmd/haven-console/dist

console-build: ui-build
	go build -o bin/haven-console ./cmd/haven-console

console-test:
	go test ./internal/...

console-run: console-build
	./bin/haven-console

controller-build:
	go build -o bin/haven-controller ./cmd/haven-controller

controller-deploy: controller-build
	kubectl apply -f deploy/k8s/controller/deployment.yaml
	kubectl apply -f config/samples/identityplane-dev.yaml
	kubectl rollout restart deployment/haven-controller -n haven-system 2>/dev/null || true

docs-install:
	python3 -m venv .venv-docs
	.venv-docs/bin/pip install -q -r requirements-docs.txt

docs-serve: docs-install
	.venv-docs/bin/mkdocs serve

docs-build: docs-install
	.venv-docs/bin/mkdocs build --strict

image-console:
	$(DOCKER) build -f Dockerfile.console -t $(IMAGE_REGISTRY)/haven-console:$(VERSION) .

image-controller:
	$(DOCKER) build -f Dockerfile.controller -t $(IMAGE_REGISTRY)/haven-controller:$(VERSION) .

image-idp:
	$(DOCKER) build -f Dockerfile.idp -t $(IMAGE_REGISTRY)/haven-idp:$(VERSION) .

images: image-console image-controller image-idp

idp-build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/haven-idp ./cmd/haven-idp

build-haven:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/haven ./cmd/haven

idp-dev:
	go run ./cmd/haven-idp dev

# Static (CGO off) macOS binaries for both architectures: bin/darwin-{arm64,amd64}/{haven-idp,haven}.
build-darwin:
	@for arch in arm64 amd64; do \
		mkdir -p bin/darwin-$$arch; \
		for c in haven-idp haven; do \
			GOOS=darwin GOARCH=$$arch CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/darwin-$$arch/$$c ./cmd/$$c || exit 1; \
		done; \
	done

# Unsigned universal installer package (see packaging/macos/README.md for signing and notarization, which this does not do).
macos-pkg:
	bash packaging/macos/build-pkg.sh --version $(VERSION)
