.PHONY: build test golden prove vet dist

# Raise this for every release. The installer and `fenzi update` read
# latest.txt, and a release that keeps the old number is never offered.
VERSION ?= 0.1.21

build:
	go build -trimpath -o bin/fenzi ./cli

test:
	go test ./...

vet:
	go vet ./...

# Rewrite compiler golden files after an intended change. Review the diff.
golden:
	go test ./compiler -update

# Run the upstream prover on every golden policy against its boundary.
# Needs openshell-prover; no gateway.
prove:
	@command -v openshell-prover >/dev/null || { echo "openshell-prover is not installed"; exit 1; }
	@fail=0; for p in compiler/testdata/golden/*.policy.yaml; do \
		b=$${p%.policy.yaml}.boundary.yaml; \
		echo "== $$p"; \
		openshell-prover check "$$p" --boundary "$$b" --output json || fail=1; \
	done; exit $$fail

# Binaries the install script downloads. Checksums are sha256, two spaces, then the file name.
dist:
	rm -rf dist
	mkdir -p dist
	@for pair in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64; do \
		os=$${pair%/*}; arch=$${pair#*/}; \
		out=dist/fenzi-$(VERSION)-$$os-$$arch; \
		echo "== $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "-X main.Version=$(VERSION)" -o $$out ./cli; \
	done
	cd dist && shasum -a 256 fenzi-$(VERSION)-* | awk '{ print $$1 "  " $$2 }' > fenzi-$(VERSION)-sha256.txt
	# CLIs from before the rename to Fenzi update themselves by the old file
	# names, so each binary is also published as boundlane-<version>-<os>-<arch>.
	@for f in dist/fenzi-$(VERSION)-*-*; do cp "$$f" "dist/boundlane-$${f#dist/fenzi-}"; done
	cd dist && shasum -a 256 boundlane-$(VERSION)-*-* | awk '{ print $$1 "  " $$2 }' > boundlane-$(VERSION)-sha256.txt
	echo $(VERSION) > dist/latest.txt
